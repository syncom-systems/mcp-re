# SPDX-License-Identifier: Apache-2.0
"""perf on the proxy for ONE rig point, after the authoritative numbers exist."""

from __future__ import annotations

import argparse
import os
import subprocess
import time
from pathlib import Path

from ceiling_manifest import binaries, launchers
from common import base_env, log, ports, run_logged, write_json
from phases import STARTUP_LOG_ENV, startup_facts
from redis_tier import Tier


def _find_proxy(deadline_s: float = 120) -> int | None:
    """The pid of the running proxy, by executable name, polled until it appears."""
    end = time.time() + deadline_s
    while time.time() < end:
        pid = _proxy_pid_now()
        if pid is not None:
            return pid
        time.sleep(0.5)
    return None


def _proxy_pid_now() -> int | None:
    for entry in os.listdir("/proc"):
        if entry.isdigit() and _is_proxy(entry):
            return int(entry)
    return None


def _is_proxy(pid: str) -> bool:
    try:
        return os.path.basename(os.readlink(f"/proc/{pid}/exe")).startswith("mcp-re-proxy")
    except OSError:
        return False


def _perf_argv() -> list[str]:
    """perf, through `sudo -n` when not root: Ubuntu kernels set kernel.perf_event_paranoid=4,
    which refuses an unprivileged attach outright. The measured processes stay unprivileged;
    only the observer is elevated, and `-n` fails rather than prompts."""
    return ["perf"] if os.geteuid() == 0 else ["sudo", "-n", "perf"]


def _rig_environment(args, bins, tier: Tier, diag: Path) -> dict:
    return dict(base_env(), MCP_RE_SAT_REDIS_URL=tier.url, MCP_RE_SAT_WORKERS_PER_SHARD=str(args.workers),
                MCP_RE_PROXY_CLI=str(bins.proxy_ext), MCP_RE_SAT_BACKEND=str(bins.backend),
                MCP_RE_SAT_LOADGEN=str(bins.loadgen), MCP_RE_SAT_OUT=str(diag / "rig.json"),
                **{STARTUP_LOG_ENV: str(diag / "proxy-startup.log")})


def _record(args, perf: list[str], pid: int, diag: Path) -> int:
    """perf record, attached to the proxy for the window, after the warmup."""
    time.sleep(args.warmup)
    rc, _ = run_logged(perf + ["record", "-F", "99", "-g", "-p", str(pid), "-o", str(diag / "perf.data"),
                               "--", "sleep", str(args.window)], diag / "perf-record.log",
                       timeout=args.window + 120)
    return rc


def _hand_back(diag: Path) -> None:
    """Recorded as root, mode 0600: hand it back so the report, the seal and the pack
    (all unprivileged) can read it. perf report itself accepts a file the caller owns."""
    run_logged(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(diag / "perf.data")],
               diag / "perf-chown.log", timeout=60)


def _report(diag: Path) -> int:
    rc, _ = run_logged(["sh", "-c", f'perf report -i "{diag}/perf.data" --stdio --no-children '
                                    f'--percent-limit 0.5 > "{diag}/perf-report.txt" 2>&1'],
                       diag / "perf-report.log", timeout=1800)
    return rc


def _rig_with_perf(args, argv: list[str], env: dict, diag: Path) -> dict:
    """Run the rig, attach perf once the proxy appears, and report what happened."""
    perf = _perf_argv()
    record_rc = None
    with open(diag / "rig.log", "wb") as out:
        rig = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, env=env)
        pid = _find_proxy()
        if pid is not None:
            record_rc = _record(args, perf, pid, diag)
        rig_rc = rig.wait(timeout=3600)
    if perf[0] == "sudo" and (diag / "perf.data").exists():
        _hand_back(diag)
    return {"perf": perf, "pid": pid, "record_rc": record_rc, "rig_rc": rig_rc,
            "report_rc": _report(diag)}


def _write_diagnosis(args, argv: list[str], diag: Path, outcome: dict) -> None:
    write_json(diag / "diagnose.json", {"argv": argv, "proxy_pid": outcome["pid"], "window_s": args.window,
                                        "replay_pool_requested": args.replay_redis_pool_size,
                                        "proxy": startup_facts(diag / "proxy-startup.log"),
                                        "warmup_s": args.warmup, "rig_rc": outcome["rig_rc"],
                                        "perf": outcome["perf"],
                                        "perf_record_rc": outcome["record_rc"],
                                        "perf_report_rc": outcome["report_rc"]})


def _exit_code(run_dir: Path, diag: Path, outcome: dict) -> int:
    if outcome["pid"] is None:
        return 6
    if outcome["record_rc"] != 0 or outcome["report_rc"] != 0:
        log(run_dir, f"DIAGNOSE: perf failed (record rc={outcome['record_rc']}, "
                     f"report rc={outcome['report_rc']}); see {diag}")
        return 7
    return outcome["rig_rc"]


def diagnose(args: argparse.Namespace) -> int:
    """perf on the proxy for ONE rig point, after the authoritative numbers exist.

    perf ATTACHES to the running proxy (`-p`) for a fixed window; it never wraps it. The rig's
    MCP_RE_PROFILE_WRAPPER hook changes how it tears down EVERY child — the unwrapped backend
    included, which it then waits on forever — so the instrument is left exactly as measured."""
    run_dir = Path(args.run_dir).resolve()
    if not (run_dir / "summary.json").is_file():
        raise SystemExit("ceiling: diagnose runs only after the authoritative summary is written")
    diag = run_dir / "diagnostic" / f"c{args.cores}"
    diag.mkdir(parents=True, exist_ok=True)
    bins = launchers(diag, binaries(Path(args.bin_dir)), args.replay_redis_pool_size)
    tier = Tier(run_dir / "diagnostic", ports(Path(args.ports_toml)))
    tier.up(run_dir)
    try:
        argv = [str(bins.rig), "--cores", str(args.cores), "--mode", args.mode, "--fixed-generators",
                str(args.generators), "--connections", str(args.connections)]
        outcome = _rig_with_perf(args, argv, _rig_environment(args, bins, tier, diag), diag)
        _write_diagnosis(args, argv, diag, outcome)
    finally:
        tier.down()
    return _exit_code(run_dir, diag, outcome)
