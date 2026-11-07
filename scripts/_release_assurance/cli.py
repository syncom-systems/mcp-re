# SPDX-License-Identifier: Apache-2.0
"""The gate's commands: the verdict on the tree and `--verify-run`."""

from __future__ import annotations

import sys
from pathlib import Path

from _release_assurance.config import BACKING, CANONICAL, RELEASES, REPO, WORKFLOW
from _release_assurance.correspondence import correspondence_problems
from _release_assurance.invocation import invocation_problems
from _release_assurance.provenance import verify_run
from _release_assurance.records import load_record


def _verify_run_command(args: list[str]) -> int:
    index = args.index("--verify-run")
    if index + 1 >= len(args):
        raise SystemExit("--verify-run needs the record file")
    repo = args[args.index("--repo") + 1] if "--repo" in args else None
    return verify_run(Path(args[index + 1]), repo)


def _workflow_text() -> dict[str, str]:
    if (REPO / WORKFLOW).is_file():
        return {str(WORKFLOW): (REPO / WORKFLOW).read_text(encoding="utf-8")}
    return {}


def _documents() -> dict[str, str]:
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted((REPO / RELEASES).glob("*-provenance.md"))
    }


def _records() -> dict[str, dict]:
    records = {}
    for path in sorted((REPO / RELEASES).glob("*-release-assurance.json")):
        loaded = load_record(path)
        if loaded is not None:
            records[path.name] = loaded
    return records


def _verdict() -> int:
    documents = _documents()
    problems = invocation_problems(_workflow_text()) + correspondence_problems(documents, _records())
    if problems:
        print("release-assurance gate: FAIL", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    mechanized = sum(1 for name in documents if BACKING.get(name) == "mechanized")
    print(
        f"release-assurance gate: OK — {WORKFLOW.name} invokes `{CANONICAL}`; "
        f"{len(documents)} provenance document(s), {mechanized} mechanized, "
        f"{len(documents) - mechanized} pre-mechanism and recorded as such."
    )
    return 0


def run(args: list[str]) -> int:
    if "--verify-run" in args:
        return _verify_run_command(args)
    return _verdict()
