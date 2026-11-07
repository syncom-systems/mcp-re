"""The run's identity and its durable record."""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

SCHEMA = "mcp-re-slo-run/v1"

#: Where run manifests live. Durable, because reconciliation needs to read the manifest of
#: a run whose process is long gone -- and beside the evidence store rather than inside the
#: Actions checkout, which is cleaned between runs.
RUNS_ROOT = Path(os.environ.get("MCP_RE_SLO_RUNS_ROOT", "/opt/verification/slo-runs"))


class LifecycleError(RuntimeError):
    """A refusal. The caller must not measure, and must not attest."""


def run_id_from_environment() -> str:
    """Stable execution coordinates, with a nonce only where they do not exist.

    Outside Actions there is no run id to be had, so a nonce keeps two local runs from
    claiming each other's resources. Inside Actions the coordinates are stable and a nonce
    would defeat reconciliation across an attempt.
    """
    run = os.environ.get("GITHUB_RUN_ID")
    if run:
        attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
        job = os.environ.get("GITHUB_JOB", "job")
        return f"gh-{run}-{attempt}-{job}"
    return f"local-{os.getpid()}-{uuid.uuid4().hex[:8]}"


def manifest_path(run: str) -> Path:
    return RUNS_ROOT / f"{run}.json"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def write_manifest(run: str, **fields: object) -> dict:
    RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    path = manifest_path(run)
    record = json.loads(path.read_text()) if path.exists() else {
        "schema": SCHEMA, "run_id": run, "created_at": _now(), "events": []}
    record.update(fields)
    record["events"].append({"at": _now(), **{k: v for k, v in fields.items() if k != "events"}})
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True, default=str))
    os.replace(tmp, path)
    return record
