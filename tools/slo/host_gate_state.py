"""The gate's on-disk layout and its committed record: paths, the transition mutex, publication.

`fcntl` guards TRANSITIONS only, on macOS. The record is published by `os.replace`, so the
reader on the other kernel sees either the previous committed state or the new one.
"""

from __future__ import annotations

import fcntl
import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_gate_config as cfg  # noqa: E402
import host_locks  # noqa: E402
from arbiter_error import ArbiterError  # noqa: E402


def paths(root: Path | None = None, mirror: Path | None = None) -> dict[str, Path]:
    r = Path(root or cfg.ROOT)
    m = Path(mirror or cfg.MIRROR)
    return {
        "root": r, "mirror": m,
        "lock": r / "lock", "gate": r / "gate.json", "active": r / "active",
        "log": r / "arbiter.log", "mirror_gate": m / "gate.json",
        "vm_active": m / "vm-active",
        "holders": r / "holders",
    }


def ensure_layout(p: dict[str, Path]) -> None:
    p["active"].mkdir(parents=True, exist_ok=True)
    p["holders"].mkdir(parents=True, exist_ok=True)
    host_locks.ensure_lock_files(p["root"])
    p["vm_active"].mkdir(parents=True, exist_ok=True)
    if not p["lock"].exists():
        p["lock"].touch()


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log(p: dict[str, Path], event: str, **fields: object) -> None:
    rec = {"t": time.time(), "iso": now(), "event": event, **fields}
    try:
        with p["log"].open("a") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")
    except OSError:
        pass
    print(f"[host-gate] {event} {json.dumps(fields, default=str)}", file=sys.stderr)


@contextmanager
def mutex(p: dict[str, Path]):
    """Short-lived exclusive lock around one state transition.

    `fcntl.flock`, not a create-if-absent test, because

        if not path.exists(): path.write(...)

    leaves a window in which a second process passes the same test -- the very race this
    exists to close. Held only across a transition, never across a wait: a hook that slept
    holding this would deadlock every other hook on the host.
    """
    fh = p["lock"].open("a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()


def write_atomic(path: Path, payload: dict) -> None:
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str))
    os.replace(tmp, path)


def commit(p: dict[str, Path], gate: dict) -> None:
    """Publish the authoritative record, then mirror it for the other kernel."""
    write_atomic(p["gate"], gate)
    try:
        p["mirror"].mkdir(parents=True, exist_ok=True)
        write_atomic(p["mirror_gate"], gate)
    except OSError as exc:
        # A mirror we cannot publish means the VM cannot learn the decision, so the host is
        # not reservable. Surfaced rather than swallowed.
        raise ArbiterError(f"could not publish the committed gate mirror: {exc}") from exc


def read_gate(p: dict[str, Path]) -> dict:
    try:
        raw = p["gate"].read_text()
    except FileNotFoundError:
        return {"schema": cfg.SCHEMA, "state": cfg.OPEN}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        # A corrupt gate is NOT "open". Treating an unreadable record as absence is the
        # fail-open case, and it would fire exactly when the host is already in trouble.
        raise ArbiterError(
            f"gate.json is unreadable ({exc}); refusing rather than assuming the host is "
            "free. Inspect it, then use `recover` once no owner job is live."
        ) from exc


def _report(record_file: Path, source: str) -> dict:
    try:
        rec = json.loads(record_file.read_text())
    except (OSError, json.JSONDecodeError):
        rec = {"key": record_file.stem, "corrupt": True}
    rec["reported_by"] = source
    return rec


def active_records(p: dict[str, Path]) -> list[dict]:
    """macOS ACTIVE records plus whatever the VM reported about itself.

    The VM's self-report is a convenience for diagnostics, never the proof: a report that
    depends on the participant it describes cannot establish that participant is idle.
    `vm_participant.worker_count()` observes the real processes instead.
    """
    return [_report(f, source)
            for directory, source in ((p["active"], "macos"), (p["vm_active"], "vm"))
            for f in sorted(directory.glob("*.json"))]
