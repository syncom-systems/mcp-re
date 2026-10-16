# SPDX-License-Identifier: Apache-2.0
"""Shared plumbing for the Lightsail ceiling experiment: the run directory, JSON records,
the port registry and logged subprocesses. Standard library only — the host has python3 and
nothing else this tooling may assume."""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

#: The run directory is the ONE place a session's evidence lives. Every writer below takes
#: it explicitly; nothing is written beside it.
LAYOUT = (
    "manifest.json",           # identities, envelope, sweep plan, tooling revision
    "host/",                   # inventory before, after; identity check verdict
    "redis/",                  # tier config, INFO before/after, logs
    "phase-a/",                # canonical cold-mTLS curve: <topology>/c<N>/rep<i>.json + logs + telemetry
    "phase-b/",                # saturation rig: <sweep>/c<N>/try<k>.json + logs + telemetry
    "diagnostic/",             # optional profiling pass, after the authoritative numbers
    "logs/",                   # the campaign's own stdout/stderr and step timings
    "summary.json",
    "summary.md",
)

HW_CLASS = "aws-lightsail-32vcpu-v1"


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def ports(ports_toml: Path) -> dict[str, int]:
    services = tomllib.loads(ports_toml.read_text())["services"]
    return {name: int(entry["port"]) for name, entry in services.items()}


def log(run_dir: Path | None, message: str) -> None:
    line = f"[{utc_now()}] {message}"
    print(line, flush=True)
    if run_dir is not None:
        (run_dir / "logs").mkdir(parents=True, exist_ok=True)
        with open(run_dir / "logs" / "campaign.log", "a") as handle:
            handle.write(line + "\n")


def run_logged(argv: list[str], log_path: Path, env: dict[str, str] | None = None,
               timeout: float | None = None, cwd: Path | None = None) -> tuple[int, float]:
    """Run argv with stdout+stderr captured in full to log_path. Returns (rc, seconds).

    A timeout is a failure with rc 124 and is written into the log, never swallowed: a
    measurement that did not finish is not a measurement.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started = _dt.datetime.now().timestamp()
    with open(log_path, "wb") as out:
        out.write(f"$ {' '.join(argv)}\n".encode())
        out.flush()
        try:
            proc = subprocess.run(argv, stdout=out, stderr=subprocess.STDOUT, env=env,
                                  timeout=timeout, cwd=cwd)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            out.write(f"\n### TIMEOUT after {timeout}s\n".encode())
            rc = 124
    return rc, _dt.datetime.now().timestamp() - started


def base_env() -> dict[str, str]:
    """The inherited environment minus anything that would redirect a binary's runfiles:
    the instruments are run as plain binaries with absolute paths, never via Bazel."""
    env = {k: v for k, v in os.environ.items() if k not in {"RUNFILES_DIR", "TEST_SRCDIR", "RUNFILES_MANIFEST_FILE"}}
    env.setdefault("RUST_BACKTRACE", "1")
    return env


def die(message: str, code: int = 1) -> "None":
    print(f"ceiling: {message}", file=sys.stderr)
    raise SystemExit(code)
