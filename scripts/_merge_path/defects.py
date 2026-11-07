# SPDX-License-Identifier: Apache-2.0
"""The gate's verdicts: controls the merge path does not run, entry points it does not reach,
registry rows that disagree with the files, and exemptions that name nothing."""

from __future__ import annotations

from dataclasses import dataclass, field

from _merge_path.config import ENTRY_ROOT, _gates


@dataclass(frozen=True)
class Coverage:
    """What the unconditional workflows name, and what only a `paths:`-filtered one does."""

    covered: set[str]
    filtered_only: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class EntryReach:
    """How the merge path reaches entry points: named by an unconditional workflow, or
    dispatched through the lane catalogue; `dispatch_problem` says why the catalogue could
    not be read."""

    unconditional: set[str]
    dispatched: set[str]
    filtered_only: set[str] = field(default_factory=set)
    dispatch_problem: str | None = None


def exemptions(rows: dict[str, _gates.Gate]) -> tuple[dict[str, str], dict[str, str]]:
    """`(script exemptions, entry-point exemptions)`, from the rows' `off_merge_path`.

    Split by where the path lives, because the two halves of this gate ask different things
    of an exemption: a script exemption must name something `local_gate.sh` invokes, an
    entry-point exemption something under `tools/verification/` that is an entry point.
    Both are printed on every run and checked for dead entries: an exemption naming nothing
    either check would flag is a claim about nothing.
    """
    scripts: dict[str, str] = {}
    entries: dict[str, str] = {}
    for path, gate in rows.items():
        if gate.off_merge_path:
            target = entries if path.startswith(f"{ENTRY_ROOT}/") else scripts
            target[path] = gate.off_merge_path
    return scripts, entries


def _uncovered_script(script: str, filtered_only: set[str]) -> str:
    if script in filtered_only:
        return (
            f"{script} is named only by a `paths:`-filtered workflow. It therefore runs "
            f"on the pull requests that touch those paths and on no others, while "
            f"reading as enforced. Move it to an unconditional job, or give its row in {_gates.REGISTRY} an "
            f"`off_merge_path` stating why its scope really is that filter."
        )
    return (
        f"{script} runs only in scripts/local_gate.sh. A control the assurance model "
        f"relies on must be present on the merge path; add it to a workflow, or give its "
        f"row in {_gates.REGISTRY} an `off_merge_path` stating why it is deliberately local."
    )


def _uncovered_selftest(script: str) -> str:
    return (
        f"{script} is an assurance-platform self-test that no unconditional workflow "
        f"names. These suites are what establishes that a `verify` verdict means what "
        f"ADR-MCPRE-059 says it means; one that runs conditionally, or not at all, "
        f"leaves that meaning unestablished on every pull request that does not trip "
        f"its filter."
    )


def _dead_script_exemption(script: str) -> str:
    return (
        f"{script} carries `off_merge_path` in {_gates.REGISTRY}, and scripts/local_gate.sh "
        f"does not invoke it. A dead exemption is a claim about nothing and hides the next "
        f"one that matters."
    )


def defects(
    gated: set[str],
    coverage: Coverage,
    exempt: dict[str, str],
    selftests: set[str] | None = None,
) -> list[str]:
    """Controls the merge path does not run, and exemptions that name nothing."""
    covered = coverage.covered
    selftests = selftests or set()
    found = [
        _uncovered_script(script, coverage.filtered_only)
        for script in sorted(gated - covered - exempt.keys())
    ]
    found.extend(
        _uncovered_selftest(script) for script in sorted(selftests - covered - exempt.keys())
    )
    found.extend(
        _dead_script_exemption(script)
        for script in sorted(exempt.keys() - gated - selftests)
    )
    return found


def _unreached_entry_point(script: str, filtered_only: set[str]) -> str:
    why = (
        "is named only by a `paths:`-filtered workflow, so it runs on the pull requests "
        "that touch those paths and on no others"
        if script in filtered_only
        else "is reached by no unconditional workflow and by no dispatcher that one reaches"
    )
    return (
        f"{script} {why}. It is an assurance-platform entry point — an executable file "
        f"under {ENTRY_ROOT}/ — so something is meant to run it. Name it in an "
        f"unconditional workflow, run it from a reached dispatcher, or give its row in "
        f"{_gates.REGISTRY} an `off_merge_path` stating why it decides nothing."
    )


def _dead_entry_exemption(script: str) -> str:
    return (
        f"{script} carries `off_merge_path` in {_gates.REGISTRY} and is not an "
        f"assurance-platform entry point in this tree. A dead exemption is a claim about "
        f"nothing and hides the next one that matters."
    )


def entry_point_defects(
    population: set[str],
    reach: EntryReach,
    exempt: dict[str, str],
) -> list[str]:
    """Entry points the merge path does not reach, and exemptions that name nothing."""
    found: list[str] = []
    if reach.dispatch_problem:
        found.append(
            f"{reach.dispatch_problem}. Every lane's entry point is reached through that table, "
            f"so this gate cannot say which lanes run until it can be read."
        )
    found.extend(
        _unreached_entry_point(script, reach.filtered_only)
        for script in sorted(population - reach.unconditional - reach.dispatched - exempt.keys())
    )
    found.extend(
        _dead_entry_exemption(script) for script in sorted(exempt.keys() - population)
    )
    return found


def _stages_defect(path: str, gate: _gates.Gate, actual: tuple[int, ...]) -> str:
    return (
        f"{path}: {_gates.REGISTRY} says `stages = {list(gate.stages)}` and "
        f"scripts/local_gate.sh runs it in stages {list(actual)}. Correct the row."
    )


def _ci_defect(path: str, gate: _gates.Gate, actual: tuple[str, ...]) -> str:
    return (
        f"{path}: {_gates.REGISTRY} says `ci = {list(gate.ci)}` and the workflows "
        f"name it in {list(actual)}. Correct the row."
    )


def registry_defects(
    rows: dict[str, _gates.Gate],
    stages: dict[str, set[int]],
    jobs: dict[str, set[str]],
) -> list[str]:
    """Rows whose `stages` or `ci` disagree with `local_gate.sh` and the workflows."""
    found: list[str] = []
    for path, gate in sorted(rows.items()):
        actual_stages = tuple(sorted(stages.get(path, ())))
        if gate.stages != actual_stages:
            found.append(_stages_defect(path, gate, actual_stages))
        actual_jobs = tuple(sorted(jobs.get(path, ())))
        if gate.ci != actual_jobs:
            found.append(_ci_defect(path, gate, actual_jobs))
    return found
