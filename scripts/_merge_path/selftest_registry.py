# SPDX-License-Identifier: Apache-2.0
"""Selftest: the gate registry — stages reached through function calls, workflow jobs,
rows against both, and the exemption split."""

from __future__ import annotations

from _merge_path.config import ENTRY_ROOT, _gates
from _merge_path.defects import exemptions, registry_defects
from _merge_path.reach import local_gate_stages, workflow_jobs
from _merge_path.selftest_support import expect
from workflow_reader import parse

_STAGE_TEXT = (
    "one() {\n  helper\n}\n"
    "helper() {\n  python3 scripts/a_gate.py\n}\n"
    "two() {\n  bash scripts/b.sh && helper\n}\n"
    'run "first" one\nrun "second" two\n'
)

_WORKFLOW = (
    "on:\n  pull_request:\njobs:\n  rust:\n    steps:\n      - run: python3 scripts/a_gate.py\n"
    "  docs:\n    steps:\n      - run: tools/verification/check-views\n"
)

_ROW = (
    '[[script]]\npath = "scripts/a_gate.py"\nstages = [1, 2]\nci = ["w.yml:rust"]\nselftest = true\n'
)

_EXEMPTIONS = (
    '[[script]]\npath = "scripts/x.sh"\nstages = []\nci = []\nselftest = false\noff_merge_path = "a demo"\n'
    f'[[script]]\npath = "{ENTRY_ROOT}/report"\nstages = []\nci = []\nselftest = false\noff_merge_path = "a report"\n'
)


def _job_keys(jobs: dict[str, set[str]], path: str) -> set[str]:
    return {job.rsplit(":", 1)[1] for job in jobs[path]}


def _check_stages() -> dict[str, set[int]]:
    stages = local_gate_stages(_STAGE_TEXT)
    expect(
        stages == {"scripts/a_gate.py": {1, 2}, "scripts/b.sh": {2}},
        f"local_gate stages read as {stages!r}",
    )
    return stages


def _check_jobs() -> None:
    jobs = workflow_jobs([parse(_WORKFLOW)])
    expect(
        set(jobs) == {"scripts/a_gate.py", "tools/verification/check-views"}
        and _job_keys(jobs, "scripts/a_gate.py") == {"rust"}
        and _job_keys(jobs, "tools/verification/check-views") == {"docs"},
        f"workflow jobs read as {jobs!r}",
    )


def _check_rows(stages: dict[str, set[int]]) -> None:
    row = _gates.parse(_ROW)
    agree = {"scripts/a_gate.py": {"w.yml:rust"}}
    expect(
        not registry_defects(row, stages, agree),
        "a row agreeing with local_gate.sh and the workflows was refused",
    )
    expect(
        any("stages" in d for d in registry_defects(row, {"scripts/a_gate.py": {1}}, agree)),
        "a row whose stages local_gate.sh contradicts passed",
    )
    expect(
        any("`ci =" in d for d in registry_defects(row, stages, {})),
        "a row whose workflow jobs the workflows contradict passed",
    )


def _check_exemptions() -> None:
    split = exemptions(_gates.parse(_EXEMPTIONS))
    expect(
        split == ({"scripts/x.sh": "a demo"}, {f"{ENTRY_ROOT}/report": "a report"}),
        f"exemptions split as {split!r}",
    )
    expect(_gates.selftest() == 0, "the gate registry reader's own selftest")


def check() -> None:
    stages = _check_stages()
    _check_jobs()
    _check_rows(stages)
    _check_exemptions()
