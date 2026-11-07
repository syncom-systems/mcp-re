# SPDX-License-Identifier: Apache-2.0
"""Running the gate over the tree: gather what the merge path names and runs, judge it, and
report."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from _merge_path.config import ENTRY_ROOT, LOCAL_GATE, REPO, SELFTEST_GLOB, _gates
from _merge_path.defects import (
    Coverage,
    EntryReach,
    defects,
    entry_point_defects,
    exemptions,
    registry_defects,
)
from _merge_path.extract import command_position_paths, invoked_by, not_executable, truncating_fetches
from _merge_path.reach import (
    dispatched_entry_points,
    entry_points,
    local_gate_stages,
    workflow_coverage,
    workflow_entry_coverage,
    workflow_jobs,
)
from workflow_reader import shell_commands, workflows


class GateFailure(Exception):
    """The gate could not measure, which is a failure and never a silent pass."""


@dataclass(frozen=True)
class Scope:
    """What the local aggregate, the workflows and the registry say, read once."""

    gated: set[str]
    rows: dict[str, _gates.Gate]
    exempt: dict[str, str]
    exempt_entry: dict[str, str]
    covered: set[str]
    filtered_only: set[str]
    selftests: set[str]
    runnable: set[str]
    truncating: list[str]


def _truncating_message(workflow, line: str) -> str:
    return (
        f"{Path(workflow.path).name}: `{line}` SHALLOWS a clone its job took at "
        f"`fetch-depth: 0`. A shallow fetch truncates the object graph rather than "
        f"extending it, so every later step that asks an ancestry question measures a "
        f"history that is no longer there. Drop the depth flag, or read the ref the "
        f"deep checkout already provides."
    )


def _runnable_and_truncating() -> tuple[set[str], list[str]]:
    """Paths run as programs by the aggregate or a workflow, and the shallowing fetches."""
    runnable = command_position_paths(shell_commands(LOCAL_GATE.read_text(encoding="utf-8")))
    truncating: list[str] = []
    for workflow in workflows(REPO):
        runnable |= command_position_paths(workflow.commands())
        truncating += [
            _truncating_message(workflow, line) for line in truncating_fetches(workflow)
        ]
    return runnable, truncating


def _load_rows() -> dict[str, _gates.Gate]:
    try:
        return _gates.load(REPO)
    except _gates.RegistryError as exc:
        raise GateFailure(str(exc)) from exc


def _platform_selftests() -> set[str]:
    return {path.relative_to(REPO).as_posix() for path in REPO.glob(SELFTEST_GLOB)}


def _load_scope() -> Scope:
    gated = invoked_by(LOCAL_GATE)
    if not gated:
        # An empty scope is the gate measuring nothing while printing OK.
        raise GateFailure(
            f"merge-path gate found no script invocations in {LOCAL_GATE}. "
            f"The extractor has stopped matching."
        )
    rows = _load_rows()
    exempt, exempt_entry = exemptions(rows)
    covered, filtered_only = workflow_coverage()
    selftests = _platform_selftests()
    if not selftests:
        raise GateFailure(
            f"no assurance-platform self-test matched {SELFTEST_GLOB}. An empty "
            f"scope is the gate measuring nothing while printing OK."
        )
    runnable, truncating = _runnable_and_truncating()
    return Scope(
        gated, rows, exempt, exempt_entry, covered, filtered_only, selftests, runnable, truncating
    )


def _not_executable_message(path: str) -> str:
    return (
        f"{path} is invoked as a program by local_gate.sh or a workflow and is NOT "
        f"executable. A control that cannot start is not enforced — this is `Permission "
        f"denied`, stage 1, on every fresh checkout. Stage the mode: "
        f"`git update-index --chmod=+x {path}`."
    )


def _script_defects(scope: Scope) -> list[str]:
    found = list(scope.truncating)
    found += [_not_executable_message(path) for path in not_executable(scope.runnable)]
    found += defects(
        scope.gated,
        Coverage(scope.covered, scope.filtered_only),
        scope.exempt,
        scope.selftests,
    )
    found += _gates.problems(scope.rows, REPO)
    found += registry_defects(
        scope.rows,
        local_gate_stages(LOCAL_GATE.read_text(encoding="utf-8")),
        workflow_jobs(list(workflows(REPO))),
    )
    return found


@dataclass(frozen=True)
class EntryReport:
    """The entry-point half's findings and the numbers its OK line reports."""

    population: set[str]
    unconditional: set[str]
    dispatched: set[str]
    defects: list[str]


def _entry_report(scope: Scope) -> EntryReport:
    """THE DEFINED POPULATION. The sets in `Scope` are places someone thought to look; this
    one is every executable file under tools/verification/, which is what makes a file an
    entry point at all."""
    population = entry_points(REPO)
    if not population:
        raise GateFailure(
            f"no assurance-platform entry point found under {ENTRY_ROOT}/. The "
            f"population is defined by the execute bit, and an empty one means the "
            f"definition stopped matching — not that the platform has no controls."
        )
    unconditional, filtered = workflow_entry_coverage(REPO)
    dispatched, dispatch_problem = dispatched_entry_points(REPO)
    found = entry_point_defects(
        population,
        EntryReach(unconditional, dispatched, filtered, dispatch_problem),
        scope.exempt_entry,
    )
    return EntryReport(population, unconditional, dispatched, found)


def _print_script_ok(scope: Scope) -> None:
    listed = ", ".join(f"{name} ({why})" for name, why in sorted(scope.exempt.items()))
    print(
        f"merge-path gate: OK — {len(scope.gated)} script(s) invoked by local_gate.sh and "
        f"{len(scope.selftests)} platform self-test(s), all named by an UNCONDITIONAL workflow "
        f"except: {listed}; {len(scope.runnable)} path(s) run as programs, all executable"
    )


def _print_registry_ok(scope: Scope) -> None:
    print(
        f"merge-path gate: OK — {len(scope.rows)} row(s) in {_gates.REGISTRY}, one for each of the "
        f"{len(_gates.population(REPO))} script(s) under {_gates.SCRIPTS}/ and each exemption "
        f"outside it, every row's stages and workflow jobs matching local_gate.sh and the "
        f"workflows; {len(_gates.not_controls(scope.rows))} marked not a control"
    )


def _print_entry_ok(scope: Scope, entry: EntryReport) -> None:
    entry_exemptions = ", ".join(
        f"{name.rsplit('/', 1)[-1]} ({why})" for name, why in sorted(scope.exempt_entry.items())
    )
    print(
        f"merge-path gate: OK — {len(entry.population)} assurance-platform entry point(s) under "
        f"{ENTRY_ROOT}/, {len(entry.unconditional & entry.population)} named by an unconditional "
        f"workflow and {len(entry.dispatched & entry.population)} dispatched through the lane catalogue verify runs; "
        f"exempt: {entry_exemptions}"
    )


def judge() -> int:
    """Run the gate over the tree: `0` when every control is reached, `1` otherwise."""
    try:
        scope = _load_scope()
        found = _script_defects(scope)
        entry = _entry_report(scope)
    except GateFailure as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    found += entry.defects
    for defect in found:
        print(f"FAIL: {defect}", file=sys.stderr)
    if found:
        return 1
    _print_script_ok(scope)
    _print_registry_ok(scope)
    _print_entry_ok(scope, entry)
    return 0
