"""Shared fixtures for the host-gate controls: identities, temp roots, stand-in jobs, waits.

Everything here runs against temp directories: no helper writes /opt, and none needs a
runner. The results of every `check` accumulate in PASSED and FAILED, which the runner
`test_host_gate.py` reports.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_gate  # noqa: E402
import host_locks  # noqa: E402
from arbiter_error import ArbiterError  # noqa: E402
from job_identity import JobIdentity  # noqa: E402

PASSED: list[str] = []
FAILED: list[str] = []

CODE_REPO = "matssun/code"
MCPRE_REPO = "matssun/mcp-re"
CI_WORKFLOW = ".github/workflows/ci.yml"
SLO_WORKFLOW = ".github/workflows/slo.yml"
RETENTION_WORKFLOW = ".github/workflows/disk-retention.yml"
ARBITER = Path(__file__).resolve().parent / "runner_arbiter.py"

FAST = {"gate_wait": 1, "heavy_wait": 1, "drain_wait": 2}
STARTED_WORKERS: list = []


def workflow_ref(repository: str, workflow: str) -> str:
    """The shape GitHub puts in GITHUB_WORKFLOW_REF."""
    return f"{repository}/{workflow}@refs/heads/main"


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    mark = "ok  " if condition else "FAIL"
    suffix = f"  [{detail}]" if detail and not condition else ""
    print(f"  {mark} {name}{suffix}")


def fresh() -> dict:
    tmp = Path(tempfile.mkdtemp())
    paths = host_gate.paths(tmp / "root", tmp / "mirror")
    host_gate.ensure_layout(paths)
    return paths


def ordinary(n: int = 1, runner: str = "dev1") -> JobIdentity:
    return JobIdentity(runner, CODE_REPO, workflow_ref(CODE_REPO, CI_WORKFLOW),
                       CI_WORKFLOW, str(n), "1", f"job{n}")


def slo(n: int = 99, runner: str = "dev1-mcp-re") -> JobIdentity:
    return JobIdentity(runner, MCPRE_REPO, workflow_ref(MCPRE_REPO, SLO_WORKFLOW),
                       SLO_WORKFLOW, str(n), "1", "slo")


def recovery(n: int = 700) -> JobIdentity:
    """The lane that makes the disk not-full, as GitHub presents it to the hook."""
    return JobIdentity("dev1", CODE_REPO, workflow_ref(CODE_REPO, RETENTION_WORKFLOW),
                       RETENTION_WORKFLOW, str(n), "1", "retention")


class Job:
    """A job as the gate sees it: a stand-in Runner.Worker (a real process) and its holder."""

    def __init__(self, paths: dict, ident: JobIdentity) -> None:
        self.paths, self.ident = paths, ident
        self.worker = subprocess.Popen(["sleep", "600"])
        STARTED_WORKERS.append(self.worker)
        self.holder = None

    def admit(self, **bounds) -> "Job":
        self.holder = host_gate.admit_job(self.paths, self.ident, host_gate.Watch(self.worker.pid),
                                          bounds={**FAST, **bounds})
        return self

    def end(self) -> None:
        """The worker exits -- what happens when the job ends, is cancelled, or dies."""
        if self.worker.poll() is None:
            self.worker.kill()
            self.worker.wait()


def admitted(paths: dict, ident: JobIdentity, **bounds) -> Job:
    return Job(paths, ident).admit(**bounds)


def refusal(paths: dict, ident: JobIdentity, **bounds) -> str | None:
    """The refusal message, or None if the job was admitted (it is then ended)."""
    job = Job(paths, ident)
    try:
        job.admit(**bounds)
    except ArbiterError as exc:
        job.end()
        return str(exc)
    job.end()
    return None


def within(predicate, timeout: float = 3.0) -> float | None:
    """Seconds until `predicate()` held, or None if it never did within `timeout`."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if predicate():
            return time.monotonic() - start
        time.sleep(0.005)
    return None


def locks(paths: dict) -> dict:
    return host_locks.lock_state(paths["root"])


def all_free(paths: dict) -> bool:
    return all(v == "free" for v in locks(paths).values())


def in_thread(fn) -> dict:
    """Run `fn` in a thread; the returned dict gets "result" or "error" when it finishes."""
    box: dict = {}

    def run() -> None:
        try:
            box["result"] = fn()
        except Exception as exc:  # noqa: BLE001 -- reported by the caller
            box["error"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    box["thread"] = t
    return box


def finished(box: dict) -> bool:
    return "result" in box or "error" in box


def admits(fn) -> bool:
    """Whether `fn` completes without the gate refusing."""
    try:
        fn()
    except ArbiterError:
        return False
    return True


def refuses(fn) -> bool:
    """Whether `fn` is refused by the gate."""
    return not admits(fn)


@contextmanager
def environment(**overrides: str):
    """Run with `overrides` added to the process environment; the original is restored."""
    saved = dict(os.environ)
    os.environ.update(overrides)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)
