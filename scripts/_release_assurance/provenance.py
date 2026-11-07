# SPDX-License-Identifier: Apache-2.0
"""PROVENANCE: what GitHub records about the producing run, against the record about to be committed."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from _release_assurance.config import REPO, WORKFLOW
from _release_assurance.records import load_record_obj, producer_problems


def _run_identity_problems(run: dict) -> list[str]:
    problems = []
    # Measured 2026-10-15: this API returns the bare path. GitHub documents a `@<ref>` suffix
    # form too, which is accepted only when the ref is main.
    path, _, ref = str(run.get("path") or "").partition("@")
    if path != str(WORKFLOW) or ref not in ("", "main", "refs/heads/main"):
        problems.append(f"run is of {run.get('path')!r}, not {WORKFLOW} on main")
    if run.get("head_branch") != "main":
        problems.append(f"run was dispatched from {run.get('head_branch')!r}, not main")
    if run.get("event") != "workflow_dispatch":
        problems.append(f"run event is {run.get('event')!r}, not workflow_dispatch")
    if run.get("conclusion") != "success":
        problems.append(f"run concluded {run.get('conclusion')!r}, not success")
    return problems


def _artifact_problems(artifact: bytes | None, committed: bytes) -> list[str]:
    if artifact is None:
        return ["the run's release-assurance artifact could not be read"]
    if artifact != committed:
        return ["the run's uploaded record is not byte-identical to this file"]
    return []


def run_provenance_problems(run: dict, artifact: bytes | None, committed: bytes) -> list[str]:
    """What GitHub records about the producing run, against the record about to be committed."""
    return _run_identity_problems(run) + _artifact_problems(artifact, committed)


def gh_run(repo: str | None, run_id: str) -> dict:
    where = repo or "{owner}/{repo}"
    proc = subprocess.run(
        ["gh", "api", f"repos/{where}/actions/runs/{run_id}"],
        cwd=REPO, capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"release-assurance gate: cannot read run {run_id}: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def gh_artifact(repo: str | None, run_id: str, name: str) -> bytes | None:
    with tempfile.TemporaryDirectory() as scratch:
        argv = ["gh", "run", "download", run_id, "--name", name, "--dir", scratch]
        if repo:
            argv += ["--repo", repo]
        if subprocess.run(argv, cwd=REPO, capture_output=True, check=False).returncode != 0:
            return None
        path = Path(scratch) / "release-assurance.json"
        return path.read_bytes() if path.is_file() else None


def verify_run(path: Path, repo: str | None, fetch_run=gh_run, fetch_artifact=gh_artifact) -> int:
    """Before a record is committed: GitHub's account of its producing run vouches for it."""
    committed = path.read_bytes()
    record = load_record_obj(json.loads(committed))
    if record is None:
        print(f"release-assurance gate: FAIL — {path} is not a schema-2 release-assurance record")
        return 1
    problems = producer_problems(record)
    if not problems:
        run_id = record["producer"]["run_id"]
        name = f"release-assurance-{record['target']['commit']}-{run_id}"
        problems = run_provenance_problems(
            fetch_run(repo, run_id), fetch_artifact(repo, run_id, name), committed
        )
    for problem in problems:
        print(f"  - {problem}")
    verdict = "FAIL" if problems else "OK"
    print(f"release-assurance gate: {verdict} — provenance of {path.name}")
    return 1 if problems else 0
