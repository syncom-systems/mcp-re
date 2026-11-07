# SPDX-License-Identifier: Apache-2.0
"""The committed record: its rendering into a document block, its schema and its producer."""

from __future__ import annotations

import json
from pathlib import Path

from _release_assurance.config import (
    LEGACY_PRODUCER_REF_SUFFIX,
    MARKER_BEGIN,
    MARKER_END,
    PRODUCER_REF_SUFFIX,
)


def render(record: dict) -> str:
    """The document's assurance block, DERIVED from the record.

    Deliberately small: commit, tree, verdict, root completeness. A document may explain a
    result at any length it likes; what it may not do is be the authority for what the
    command returned.
    """
    target = record["target"]
    return "\n".join(
        [
            MARKER_BEGIN,
            f"| release assurance | `{record['verdict']}` |",
            f"| commit | `{target['commit']}` |",
            f"| tree | `{target['tree']}` |",
            f"| root completeness | `{record['root_completeness']}` |",
            f"| recorded at | `{record['recorded_at']}` |",
            f"| produced by | run `{record['producer']['run_id']}` |",
            MARKER_END,
        ]
    )


def block_of(text: str) -> str | None:
    """The document's marker block, or None when it carries none."""
    start = text.find(MARKER_BEGIN)
    end = text.find(MARKER_END)
    if not 0 <= start <= end:
        return None
    return text[start : end + len(MARKER_END)]


def record_name(document: str) -> str:
    """The record that backs `vX.Y.Z-provenance.md`: `vX.Y.Z-release-assurance.json`."""
    return document.replace("-provenance.md", "-release-assurance.json")


def producer_problems(record: dict, legacy_ok: bool = False) -> list[str]:
    """A committed record names a run of the release workflow on `main`.

    `legacy_ok` is True only for a document in `LEGACY_PRODUCED`, whose record was produced
    under the retired workflow path.
    """
    made = record.get("producer")
    if not isinstance(made, dict) or made.get("source") != "actions":
        return ["it was not produced by a GitHub Actions run, so no run can vouch for it"]
    problems = []
    accepted = (PRODUCER_REF_SUFFIX, LEGACY_PRODUCER_REF_SUFFIX) if legacy_ok else (PRODUCER_REF_SUFFIX,)
    if not str(made.get("workflow_ref") or "").endswith(accepted):
        problems.append(
            f"it was produced by {made.get('workflow_ref')!r}, not by a workflow ref ending "
            f"{' or '.join(repr(s) for s in accepted)}: a dispatch from another branch runs "
            "that branch's copy of the workflow"
        )
    if not str(made.get("run_id") or "").isdigit():
        problems.append("it names no producing run id")
    return problems


def load_record_obj(record: object) -> dict | None:
    """A parsed object, if it is a release-assurance record this gate can read."""
    if not isinstance(record, dict) or record.get("kind") != "release-assurance":
        return None
    if record.get("schema_version") != 2:
        return None
    return record


def load_record(path: Path) -> dict | None:
    """The record, or None — where None is 'absent, unreadable or unknown', all refusals."""
    if not path.is_file():
        return None
    try:
        return load_record_obj(json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        return None
