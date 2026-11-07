# SPDX-License-Identifier: Apache-2.0
"""The mutation probe. Each control is shown to FAIL on the thing it forbids."""

from __future__ import annotations

import json
import tempfile
from contextlib import contextmanager
from pathlib import Path

from _release_assurance.config import (
    BACKING,
    LEGACY_PRODUCED,
    LEGACY_PRODUCER_REF_SUFFIX,
    PRODUCER_REF_SUFFIX,
    WORKFLOW,
)
from _release_assurance.correspondence import correspondence_problems
from _release_assurance.invocation import invocation_problems
from _release_assurance.provenance import run_provenance_problems, verify_run
from _release_assurance.records import load_record, load_record_obj, producer_problems, render

DOCUMENT = "v9.9.9-provenance.md"
RECORD_FILE = "v9.9.9-release-assurance.json"


def _workflow(steps: str) -> str:
    return "jobs:\n  release-assurance:\n    steps:\n" + steps


def _invocation_controls() -> None:
    good = _workflow("      - run: python3 tools/verification/release-assurance\n")
    assert not invocation_problems({str(WORKFLOW): good})
    assert invocation_problems({}), "an absent workflow must fail"
    assert invocation_problems(
        {str(WORKFLOW): _workflow("      # runs tools/verification/release-assurance\n      - run: true\n")}
    ), "a comment naming the command is not a caller"
    assert invocation_problems(
        {str(WORKFLOW): _workflow("      - name: tools/verification/release-assurance\n        run: true\n")}
    ), "a step NAME is not a caller"
    assert invocation_problems(
        {str(WORKFLOW): _workflow('      - run: echo "next: tools/verification/release-assurance"\n')}
    ), "a usage line is not a caller"
    assert not invocation_problems(
        {str(WORKFLOW): _workflow("      - run: FOO=1 python3 ./tools/verification/release-assurance --out x\n")}
    ), "assignments and an interpreter may precede the command"
    assert not invocation_problems(
        {str(WORKFLOW): _workflow("      - run: |\n          python3 tools/verification/release-assurance \\\n            --target x\n")}
    ), "a continued command is one call"
    assert invocation_problems({str(WORKFLOW): "x: &anchor 1\n"}), "an unreadable workflow must fail"


def _record() -> dict:
    return {
        "kind": "release-assurance",
        "schema_version": 2,
        "verdict": "PASS",
        "root_completeness": "PASS",
        "recorded_at": "2026-01-01T00:00:00Z",
        "target": {"repository": "r", "commit": "c" * 40, "tree": "t" * 40},
        "producer": {
            "source": "actions",
            "workflow_ref": f"o/r{PRODUCER_REF_SUFFIX}",
            "run_id": "42",
            "run_attempt": "1",
        },
    }


@contextmanager
def _registered(document: str):
    """`document` registered as mechanized in BACKING for the duration of the block."""
    BACKING[document] = "mechanized"
    try:
        yield
    finally:
        del BACKING[document]


def _with_producer(record: dict, **producer) -> dict:
    return dict(record, producer=dict(record["producer"], **producer))


def _registry_controls(record: dict, records: dict[str, dict]) -> None:
    assert not correspondence_problems({"v0.16.0-provenance.md": "anything"}, records)
    assert correspondence_problems({DOCUMENT: "x"}, records), "unregistered refuses"


def _document_controls(record: dict, records: dict[str, dict]) -> None:
    assert correspondence_problems({DOCUMENT: "no block"}, records)
    matching = "intro\n" + render(record) + "\noutro"
    assert not correspondence_problems({DOCUMENT: matching}, records)
    assert correspondence_problems({DOCUMENT: matching}, {}), (
        "a missing record must refuse a mechanized document, never pass it"
    )
    lying = matching.replace("`PASS`", "`FAIL`", 1)
    assert correspondence_problems({DOCUMENT: lying}, records), (
        "a document claiming a verdict the record does not carry must fail"
    )
    wrong_sha = matching.replace("c" * 40, "d" * 40)
    assert correspondence_problems({DOCUMENT: wrong_sha}, records), (
        "a document naming a different target than the record must fail"
    )


def _producer_controls(record: dict) -> None:
    matching = "intro\n" + render(record) + "\noutro"
    branch = _with_producer(record, workflow_ref=f"o/r/{WORKFLOW}@refs/heads/x")
    assert correspondence_problems({DOCUMENT: matching}, {RECORD_FILE: branch}), (
        "a record produced by another branch's copy of the workflow must fail"
    )
    local = dict(record, producer={"source": "local", "workflow_ref": None, "run_id": None})
    assert correspondence_problems({DOCUMENT: matching}, {RECORD_FILE: local}), (
        "a record no Actions run produced must fail"
    )
    legacy = _with_producer(record, workflow_ref=f"o/r{LEGACY_PRODUCER_REF_SUFFIX}")
    assert correspondence_problems({DOCUMENT: matching}, {RECORD_FILE: legacy}), (
        "the retired workflow path is not a producer for a document outside LEGACY_PRODUCED"
    )
    assert not producer_problems(legacy, legacy_ok=True), (
        "the retired path must be accepted for a document in LEGACY_PRODUCED"
    )
    assert producer_problems(legacy), "the retired path is refused by default"
    assert producer_problems(branch, legacy_ok=True), (
        "legacy status accepts the retired path on main, not another branch's copy"
    )
    assert LEGACY_PRODUCED <= set(BACKING), "a legacy exception must name a registered document"
    assert load_record_obj(dict(record, schema_version=99)) is None, (
        "an unknown schema version is refused rather than read optimistically"
    )


def _correspondence_controls() -> None:
    record = _record()
    records = {RECORD_FILE: record}
    _registry_controls(record, records)
    with _registered(DOCUMENT):
        _document_controls(record, records)
        _producer_controls(record)
    assert load_record(Path("/nonexistent/x.json")) is None


def _good_run() -> dict:
    return {"path": str(WORKFLOW), "head_branch": "main", "event": "workflow_dispatch", "conclusion": "success"}


def _run_controls() -> None:
    good_run = _good_run()
    assert run_provenance_problems(good_run, b"x", b"x") == []
    assert run_provenance_problems(dict(good_run, path=f"{WORKFLOW}@main"), b"x", b"x") == []
    for field, value in (("path", ".github/workflows/other.yml"), ("path", f"{WORKFLOW}@x"), ("head_branch", "x"),
                         ("event", "push"), ("conclusion", "failure")):
        assert run_provenance_problems(dict(good_run, **{field: value}), b"x", b"x"), (
            f"a run whose {field} is {value!r} must not vouch for a record"
        )
    assert run_provenance_problems(good_run, b"y", b"x"), "a different uploaded record must fail"
    assert run_provenance_problems(good_run, None, b"x"), "an unreadable artifact must fail"


def _verify_run_controls() -> None:
    good_run = _good_run()
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / RECORD_FILE
        body = json.dumps(_record()).encode()
        path.write_bytes(body)
        asked = []

        def fetch_artifact(repo, run_id, name):
            asked.append(name)
            return body

        assert verify_run(path, None, lambda repo, run_id: good_run, fetch_artifact) == 0
        assert asked == [f"release-assurance-{'c' * 40}-42"], asked
        assert verify_run(path, None, lambda repo, run_id: dict(good_run, head_branch="x"), fetch_artifact) == 1


def selftest() -> int:
    _invocation_controls()
    _correspondence_controls()
    _run_controls()
    _verify_run_controls()
    print("release-assurance gate selftest: OK")
    return 0
