#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""MCP-RE scaling and ceiling experiment on one Linux host (the Lightsail 32-vCPU context).

Run on the measurement host, against binaries built from the released subject:

  ceiling.py campaign  RUN_DIR --bin-dir DIR --identity identity.json [--ports-toml F]
  ceiling.py inventory RUN_DIR [--expect-vcpus 32 --expect-arch x86_64 --expect-mem-gib 128]
  ceiling.py summarize RUN_DIR
  ceiling.py pack      RUN_DIR                            # final SHA256SUMS + RUN_DIR.tar.gz(.sha256)
  ceiling.py diagnose  RUN_DIR --bin-dir DIR --cores N   # perf pass, AFTER the authoritative run
  ceiling.py selftest                                     # local, no host, no cloud

The campaign: identity check -> replay tier up -> smoke -> Phase A (canonical cold-mTLS
harness, scaling topology 1..32, then the shipped auto topology) -> Phase B (saturation rig:
cold scaling sweep, repeats at the knee and the high-core region, keep-alive sweep, a
CPU-partitioned attribution sweep, the shipped auto topology) -> summary. Every step is
timed and logged into RUN_DIR; a failed point is recorded and the campaign continues, while a
host that is not the declared context, or a smoke that fails, stops it before the sweep.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tarfile
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Every file the instruments create is created under this mask. The proxy refuses a
# group-writable trust document, and an interactive Ubuntu login (the `ubuntu` user over SSH,
# then tmux) runs with umask 0002 — under that mask the harness's own trust file is refused
# and the smoke fails. The mask is part of the instrument's environment, so it is fixed here
# and recorded in the manifest next to the one inherited.
UMASK = 0o022
INHERITED_UMASK = os.umask(UMASK)
sys.path.insert(0, str(HERE))

from analysis import RULES, render_markdown, summarize_run  # noqa: E402
from common import HW_CLASS, base_env, log, ports, read_json, run_logged, sha256_file, utc_now, write_json  # noqa: E402
from hostfacts import check_expected, inventory  # noqa: E402
from phases import Binaries, Context, phase_a_point, phase_b_point  # noqa: E402
from redis_tier import Tier  # noqa: E402

SWEEP = (1, 2, 4, 8, 16, 24, 32)
BIN_NAMES = {"proxy_deploy": "mcp-re-proxy-deploy", "proxy_ext": "mcp-re-proxy-ext",
             "bench": "tls_load_harness_bench", "rig": "saturation_rig",
             "backend": "saturation_backend", "loadgen": "saturation_loadgen"}


def binaries(bin_dir: Path) -> Binaries:
    paths = {k: (bin_dir / v).resolve() for k, v in BIN_NAMES.items()}
    missing = [str(p) for p in paths.values() if not os.access(p, os.X_OK)]
    if missing:
        raise SystemExit(f"ceiling: missing or non-executable instrument(s): {missing}")
    return Binaries(**paths)


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


def repeat_cores(summary_b: dict, sweep: tuple[int, ...]) -> list[int]:
    """The knee, the point after it, and the high-core region — where stability matters."""
    chosen = {n for n in sweep if n >= 16} | set(sweep[-2:])
    curve = (summary_b.get("scaling") or {}).get("curve") or {}
    knee = curve.get("knee")
    if knee in sweep:
        i = sweep.index(knee)
        chosen |= {knee} | ({sweep[i + 1]} if i + 1 < len(sweep) else set())
    return sorted(chosen)


def campaign(args: argparse.Namespace) -> int:
    if not 2 <= args.gen_cap < 20:
        raise SystemExit("ceiling: --gen-cap must be 2..19: at 20+ generators one more adds <= 5% offered "
                         "load, so the rig's 5% criterion can no longer report CLIENT")
    run_dir = Path(args.run_dir).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    steps: list[dict] = []
    sweep = tuple(int(x) for x in args.cores.split(","))
    bins = binaries(Path(args.bin_dir))
    identity = read_json(Path(args.identity)) if args.identity else {}
    build = read_json(Path(args.build_identity)) if args.build_identity else {}
    manifest = {
        "schema": "mcp-re-lightsail-ceiling-run/v1", "started": utc_now(), "hardware_class": HW_CLASS,
        "umask": f"{UMASK:04o}", "umask_inherited": f"{INHERITED_UMASK:04o}",
        "identity": identity,
        "binaries": {k: {"path": str(getattr(bins, k)), "sha256": sha256_file(getattr(bins, k))} for k in BIN_NAMES},
        "envelope": {"concurrency": 128, "requests": 8000, "mode": "cold", "reps": args.reps,
                     "replay_tier": "redis-wait-quorum:2:2000 (primary + 2 replicas, appendonly yes, loopback)"},
        "plan": {"sweep": sweep, "phase_a_topologies": {"scaling": "WORKERS_PER_SHARD=1, --cores N",
                                                        "shipped-auto": "--cores 0 --workers-per-shard 0 (proxy defaults)"},
                 "phase_b": {"modes": args.b_modes, "repeats": args.b_repeats, "partitioned": args.partitioned,
                             "generator_cap": args.gen_cap, "connections_ladder": args.ladder,
                             "requests_per_connection": args.requests_per_connection}},
        "rules": RULES,
    }
    manifest["build"] = build
    write_json(run_dir / "manifest.json", manifest)
    # The binaries measured are the binaries the bootstrap built from the subject, or nothing.
    built = build.get("binaries", {})
    drift = [k for k, name in BIN_NAMES.items()
             if built and "sha256:" + built.get(name, "") != manifest["binaries"][k]["sha256"]]
    if drift:
        log(run_dir, f"REFUSED: instrument(s) {drift} differ from the build identity's SHA-256s")
        return 5

    facts = _step(run_dir, steps, "inventory-before", lambda: inventory(args.bundle))
    write_json(run_dir / "host" / "inventory-before.json", facts)
    problems = check_expected(facts, args.expect_vcpus, args.expect_arch, args.expect_mem_gib)
    write_json(run_dir / "host" / "identity-check.json", {"expected": {"vcpus": args.expect_vcpus,
               "arch": args.expect_arch, "mem_gib": args.expect_mem_gib}, "problems": problems})
    if problems:
        log(run_dir, "HOST IS NOT THE DECLARED MEASUREMENT CONTEXT — stopping before any measurement: " + "; ".join(problems))
        return 3
    vcpus = facts["vcpus_usable"] or os.cpu_count() or 1
    sweep = tuple(n for n in sweep if n <= vcpus)

    tier = None
    redis_url = args.redis_url
    if not redis_url:
        tier = Tier(run_dir, ports(Path(args.ports_toml)))
        _step(run_dir, steps, "redis-up", lambda: tier.up(run_dir))
        redis_url = tier.url
        tier.snapshot(run_dir / "redis" / "info-before.json")
    ctx = Context(run_dir, bins, redis_url, vcpus, args.require_telemetry, tier,
                  ladder=tuple(int(x) for x in args.ladder.split(",")), gen_cap=args.gen_cap,
                  requests_per_connection=args.requests_per_connection)
    try:
        smoke_ok = _step(run_dir, steps, "smoke", lambda: smoke(ctx))
        if not smoke_ok:
            log(run_dir, "SMOKE FAILED — the expensive sweep is not started")
            return 4
        for n in sweep:
            _tolerant(run_dir, steps, f"A-scaling-c{n}", lambda n=n: phase_a_point(ctx, "scaling", n, 1, args.reps))
        _tolerant(run_dir, steps, "A-shipped-auto", lambda: phase_a_point(ctx, "shipped-auto", 0, 0, args.reps))
        modes = [m for m in args.b_modes.split(",") if m]
        primary = modes[0] if modes else "cold"
        for n in sweep:
            _tolerant(run_dir, steps, f"B-scaling-c{n}", lambda n=n: phase_b_point(ctx, "scaling", n, 1, primary, 1))
        interim = summarize_run(run_dir, vcpus)
        for attempt in range(2, args.b_repeats + 1):
            for n in repeat_cores(interim["phase_b"], sweep):
                _tolerant(run_dir, steps, f"B-scaling-c{n}-a{attempt}",
                          lambda n=n, a=attempt: phase_b_point(ctx, "scaling", n, 1, primary, a))
        for mode in modes[1:]:
            for n in sweep:
                _tolerant(run_dir, steps, f"B-{mode}-c{n}", lambda n=n, m=mode: phase_b_point(ctx, f"scaling-{m}", n, 1, m, 1))
        for n in (int(x) for x in args.partitioned.split(",") if x):
            if n < vcpus:
                _tolerant(run_dir, steps, f"B-partitioned-c{n}",
                          lambda n=n: phase_b_point(ctx, "partitioned", n, 1, primary, 1, partition=True))
        for attempt in range(1, args.b_repeats + 1):
            _tolerant(run_dir, steps, f"B-shipped-auto-a{attempt}",
                      lambda a=attempt: phase_b_point(ctx, "shipped-auto", 0, 0, primary, a))
    finally:
        if tier is not None:
            tier.snapshot(run_dir / "redis" / "info-after.json")
            write_json(run_dir / "redis" / "health-after.json", tier.health())
            tier.down()
        write_json(run_dir / "host" / "inventory-after.json", inventory(args.bundle))
        finish(run_dir, vcpus)
    return 0


def _tolerant(run_dir: Path, steps: list, name: str, fn) -> None:
    """A failed point is recorded and the campaign continues: the machine is paid for."""
    try:
        _step(run_dir, steps, name, fn)
    except Exception:  # noqa: BLE001 — _step already wrote the error and traceback
        log(run_dir, f"step {name} FAILED (recorded in logs/steps.json); continuing")


def smoke(ctx: Context) -> bool:
    """One canonical rep at one core, and the rig's own --smoke, before anything is swept."""
    point = phase_a_point(ctx, "smoke", 1, 1, 1)
    if point["status"] != "COMPLETE":
        return False
    env = dict(base_env(), MCP_RE_SAT_REDIS_URL=ctx.redis_url, MCP_RE_PROXY_CLI=str(ctx.bins.proxy_ext),
               MCP_RE_SAT_BACKEND=str(ctx.bins.backend), MCP_RE_SAT_LOADGEN=str(ctx.bins.loadgen),
               MCP_RE_SAT_OUT=str(ctx.run_dir / "phase-a" / "smoke" / "rig-smoke.json"))
    rc, _ = run_logged([str(ctx.bins.rig), "--smoke"], ctx.run_dir / "phase-a" / "smoke" / "rig-smoke.log",
                       env=env, timeout=600)
    return rc == 0


def finish(run_dir: Path, vcpus: int) -> dict:
    summary = summarize_run(run_dir, vcpus)
    write_json(run_dir / "summary.json", summary)
    manifest = read_json(run_dir / "manifest.json")
    manifest["finished"] = utc_now()
    write_json(run_dir / "manifest.json", manifest)
    (run_dir / "summary.md").write_text(render_markdown(summary, manifest))
    log(run_dir, f"summary: {summary['ceiling']['statement']}")
    seal(run_dir)
    return summary


def seal(run_dir: Path) -> None:
    """SHA256SUMS over every file in the run directory, written after the last write to any."""
    sums = []
    for path in sorted(p for p in run_dir.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        sums.append(f"{sha256_file(path).split(':', 1)[1]}  {path.relative_to(run_dir)}")
    (run_dir / "SHA256SUMS").write_text("\n".join(sums) + "\n")


def pack(run_dir: Path) -> Path:
    """Re-seal (the launcher and a diagnose pass write after `finish`), then archive the run
    directory beside itself with a `sha256sum -c`-readable digest file."""
    seal(run_dir)
    archive = run_dir.parent / f"{run_dir.name}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(run_dir, arcname=run_dir.name)
    digest = sha256_file(archive).split(":", 1)[1]
    (run_dir.parent / f"{archive.name}.sha256").write_text(f"{digest}  {archive.name}\n")
    return archive


def _find_proxy(deadline_s: float = 120) -> int | None:
    """The pid of the running proxy, by executable name, polled until it appears."""
    end = time.time() + deadline_s
    while time.time() < end:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                try:
                    if os.path.basename(os.readlink(f"/proc/{entry}/exe")).startswith("mcp-re-proxy"):
                        return int(entry)
                except OSError:
                    continue
        time.sleep(0.5)
    return None


def diagnose(args: argparse.Namespace) -> int:
    """perf on the proxy for ONE rig point, after the authoritative numbers exist.

    perf ATTACHES to the running proxy (`-p`) for a fixed window; it never wraps it. The rig's
    MCP_RE_PROFILE_WRAPPER hook changes how it tears down EVERY child — the unwrapped backend
    included, which it then waits on forever — so the instrument is left exactly as measured."""
    import subprocess
    run_dir = Path(args.run_dir).resolve()
    if not (run_dir / "summary.json").is_file():
        raise SystemExit("ceiling: diagnose runs only after the authoritative summary is written")
    bins = binaries(Path(args.bin_dir))
    diag = run_dir / "diagnostic" / f"c{args.cores}"
    diag.mkdir(parents=True, exist_ok=True)
    tier = Tier(run_dir / "diagnostic", ports(Path(args.ports_toml)))
    tier.up(run_dir)
    try:
        env = dict(base_env(), MCP_RE_SAT_REDIS_URL=tier.url, MCP_RE_SAT_WORKERS_PER_SHARD=str(args.workers),
                   MCP_RE_PROXY_CLI=str(bins.proxy_ext), MCP_RE_SAT_BACKEND=str(bins.backend),
                   MCP_RE_SAT_LOADGEN=str(bins.loadgen), MCP_RE_SAT_OUT=str(diag / "rig.json"))
        argv = [str(bins.rig), "--cores", str(args.cores), "--mode", args.mode, "--fixed-generators",
                str(args.generators), "--connections", str(args.connections)]
        perf = _perf_argv()
        record_rc = None
        with open(diag / "rig.log", "wb") as out:
            rig = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, env=env)
            pid = _find_proxy()
            if pid is not None:
                time.sleep(args.warmup)
                record_rc, _ = run_logged(perf + ["record", "-F", "99", "-g", "-p", str(pid), "-o", str(diag / "perf.data"),
                                                  "--", "sleep", str(args.window)], diag / "perf-record.log",
                                          timeout=args.window + 120)
            rc = rig.wait(timeout=3600)
        if perf[0] == "sudo" and (diag / "perf.data").exists():
            # Recorded as root, mode 0600: hand it back so the report, the seal and the pack
            # (all unprivileged) can read it. perf report itself accepts a file the caller owns.
            run_logged(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(diag / "perf.data")],
                       diag / "perf-chown.log", timeout=60)
        report_rc, _ = run_logged(["sh", "-c", f'perf report -i "{diag}/perf.data" --stdio --no-children '
                                               f'--percent-limit 0.5 > "{diag}/perf-report.txt" 2>&1'],
                                  diag / "perf-report.log", timeout=1800)
        write_json(diag / "diagnose.json", {"argv": argv, "proxy_pid": pid, "window_s": args.window,
                                            "warmup_s": args.warmup, "rig_rc": rc, "perf": perf,
                                            "perf_record_rc": record_rc, "perf_report_rc": report_rc})
    finally:
        tier.down()
    if pid is None:
        return 6
    if record_rc != 0 or report_rc != 0:
        log(run_dir, f"DIAGNOSE: perf failed (record rc={record_rc}, report rc={report_rc}); see {diag}")
        return 7
    return rc


def _perf_argv() -> list[str]:
    """perf, through `sudo -n` when not root: Ubuntu kernels set kernel.perf_event_paranoid=4,
    which refuses an unprivileged attach outright. The measured processes stay unprivileged;
    only the observer is elevated, and `-n` fails rather than prompts."""
    return ["perf"] if os.geteuid() == 0 else ["sudo", "-n", "perf"]


def selftest() -> int:
    from selftest import run_all
    return run_all()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="ceiling.py")
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("campaign")
    c.add_argument("run_dir")
    c.add_argument("--bin-dir", required=True)
    c.add_argument("--identity")
    c.add_argument("--build-identity")
    c.add_argument("--ports-toml", default=str(HERE.parent.parent.parent / "config" / "ports.toml"))
    c.add_argument("--redis-url", help="use an operator-managed replay tier instead of starting one")
    c.add_argument("--cores", default=",".join(map(str, SWEEP)))
    c.add_argument("--reps", type=int, default=6)
    c.add_argument("--b-modes", default="cold,keepalive")
    c.add_argument("--b-repeats", type=int, default=3)
    c.add_argument("--partitioned", default="1,2,4,8,16")
    c.add_argument("--ladder", default="256,512,1024,2048", help="rig connections per generator, climbed on CLIENT")
    c.add_argument("--gen-cap", type=int, default=12, help="rig --max-generators; keep < 20 (see phases.py)")
    c.add_argument("--requests-per-connection", type=float, default=40000 / 256)
    c.add_argument("--bundle")
    c.add_argument("--expect-vcpus", type=int)
    c.add_argument("--expect-arch")
    c.add_argument("--expect-mem-gib", type=float)
    c.add_argument("--require-telemetry", action="store_true")
    i = sub.add_parser("inventory")
    i.add_argument("run_dir")
    i.add_argument("--bundle")
    i.add_argument("--expect-vcpus", type=int)
    i.add_argument("--expect-arch")
    i.add_argument("--expect-mem-gib", type=float)
    s = sub.add_parser("summarize")
    s.add_argument("run_dir")
    d = sub.add_parser("diagnose")
    d.add_argument("run_dir")
    d.add_argument("--bin-dir", required=True)
    d.add_argument("--cores", type=int, required=True)
    d.add_argument("--workers", type=int, default=1)
    d.add_argument("--mode", default="cold")
    d.add_argument("--generators", type=int, default=8)
    d.add_argument("--connections", type=int, default=256)
    d.add_argument("--warmup", type=float, default=5.0, help="seconds after the proxy appears before sampling")
    d.add_argument("--window", type=int, default=30, help="perf record window, seconds")
    d.add_argument("--ports-toml", default=str(HERE.parent.parent.parent / "config" / "ports.toml"))
    k = sub.add_parser("pack")
    k.add_argument("run_dir")
    sub.add_parser("selftest")
    args = parser.parse_args(argv)
    if args.cmd == "campaign":
        return campaign(args)
    if args.cmd == "inventory":
        facts = inventory(args.bundle)
        problems = check_expected(facts, args.expect_vcpus, args.expect_arch, args.expect_mem_gib)
        write_json(Path(args.run_dir) / "host" / "inventory.json", dict(facts, identity_problems=problems))
        print(json.dumps({"vcpus": facts["vcpus_usable"], "arch": facts["architecture"],
                          "cpu": facts["cpu_model"], "problems": problems}))
        return 3 if problems else 0
    if args.cmd == "summarize":
        run_dir = Path(args.run_dir)
        vcpus = read_json(run_dir / "host" / "inventory-before.json").get("vcpus_usable") or os.cpu_count() or 1
        print(finish(run_dir, vcpus)["ceiling"]["statement"])
        return 0
    if args.cmd == "diagnose":
        return diagnose(args)
    if args.cmd == "pack":
        print(pack(Path(args.run_dir).resolve()))
        return 0
    return selftest()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
