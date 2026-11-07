# SPDX-License-Identifier: Apache-2.0
"""What the merge path reaches: which workflows start on a pull request, which controls they
name, which entry points exist, and which stages and jobs run each path."""

from __future__ import annotations

import importlib.util
import os
import re
import sys
from pathlib import Path

from _merge_path.config import ENTRY_ROOT, FUNCTION, REPO, STAGE
from _merge_path.extract import names_in, registry_paths, scripts_in
from workflow_reader import Workflow, shell_commands, workflows


def pull_request_reach(workflow: Workflow) -> str | None:
    """`"every"` when this workflow starts on every pull request, `"filtered"` when on only
    some, `None` when on none.

    The merge path is the pull request. A workflow started only by a push to `main`, a
    schedule or a dispatch runs after the change it would refuse has merged, or never, so a
    control it names is on no merge path at all — however unfiltered its triggers are.
    """
    trigger = workflow.triggers.get("pull_request")
    if trigger is None:
        return None
    return "filtered" if trigger.filtered else "every"


def _coverage(root: Path, names) -> tuple[set[str], set[str]]:
    """`(named by an unconditional workflow, named only by a path-filtered one)`, where
    `names` reads the paths of interest out of a workflow's commands."""
    unconditional: set[str] = set()
    only_filtered: set[str] = set()
    for workflow in workflows(root):
        reach = pull_request_reach(workflow)
        if reach is not None:
            target = unconditional if reach == "every" else only_filtered
            target |= names(workflow.commands())
    return unconditional, only_filtered - unconditional


def workflow_coverage() -> tuple[set[str], set[str]]:
    """`(named by an UNCONDITIONAL workflow, named only by a path-filtered one)`.

    The split is the second half of this gate's own failure class, and it was missing.
    Being NAMED by a workflow was treated as coverage, whatever that workflow's trigger —
    so a control could sit inside a `paths:`-filtered workflow, run on the PRs that touched
    those paths, and run on no others, while this gate reported it enforced. That is the
    same defect one level up: the filter and the set of changes the control must see are
    one dependency written down twice, and when they diverge nothing goes red, the job
    simply does not start.

    It was not hypothetical. `tools/verification/test_mutation_lane.py` — the self-test for
    the mutation lane's verdict semantics — was in neither `local_gate.sh` nor any
    unconditional workflow, and was invisible here because `mutation-probe.yml` mentions it.
    """
    return _coverage(REPO, scripts_in)


def workflow_entry_coverage(root: Path) -> tuple[set[str], set[str]]:
    """`(entry points named by an UNCONDITIONAL workflow, named only by a filtered one)`."""
    return _coverage(root, names_in)


def entry_points(root: Path) -> set[str]:
    """Every assurance-platform entry point under `root`, by the definition in the gate's
    docstring.

    Executable, a regular file, directly under the directory, and not `_`-prefixed. Taking
    `root` as an argument is what lets the selftest point this at a temporary tree and
    assert the DEFINITION — that the execute bit is the discriminator and the filename is
    not — instead of re-implementing the rule and agreeing with itself.
    """
    directory = root / ENTRY_ROOT
    if not directory.is_dir():
        return set()
    return {
        f"{ENTRY_ROOT}/{path.name}"
        for path in directory.iterdir()
        if path.is_file()
        and not path.name.startswith("_")
        and os.access(path, os.X_OK)
    }


def _lane_entry_points(catalogue: Path) -> tuple[set[str], str | None]:
    """The entry points of the catalogue module's `LANES` rows, imported rather than
    pattern-matched. Raises when the module cannot be read."""
    name = "_merge_path_gate_lanes"
    try:
        spec = importlib.util.spec_from_file_location(name, catalogue)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        lanes = getattr(module, "LANES", None)
        if not lanes:
            return set(), f"{ENTRY_ROOT}/_lanes.py declares no LANES rows"
        return {f"{ENTRY_ROOT}/{lane.script}" for lane in lanes}, None
    finally:
        sys.modules.pop(name, None)


def dispatched_entry_points(root: Path) -> tuple[set[str], str | None]:
    """The lane entry points `verify` runs, read from the lane catalogue's `LANES` rows.

    `(reached, problem)`. A problem is a FAILURE and never a silent empty set: if this
    gate cannot read the one edge source it has, every lane entry point becomes an orphan
    and the run would report nine defects with one cause. Naming the cause once is the
    honest report, and a gate that quietly returned `set()` here would instead be the
    "green that measured nothing" shape with the sign flipped.
    """
    catalogue = root / ENTRY_ROOT / "_lanes.py"
    if not catalogue.is_file():
        return set(), f"{ENTRY_ROOT}/_lanes.py does not exist, so no lane has a known runner"
    try:
        return _lane_entry_points(catalogue)
    except Exception as exc:  # noqa: BLE001 - any failure to read the table is the same answer
        return set(), f"{ENTRY_ROOT}/_lanes.py's LANES rows could not be read: {exc!r}"


def _function_bodies(text: str) -> dict[str, str]:
    """Each shell function's body. A function ends at the first line that starts with `}`,
    which is how `local_gate.sh` closes every one."""
    lines = text.splitlines()
    bodies: dict[str, str] = {}
    for match in FUNCTION.finditer(text):
        first = text.count("\n", 0, match.start()) + 1
        last = first
        while last < len(lines) and not lines[last].startswith("}"):
            last += 1
        bodies[match.group(1)] = "\n".join(lines[first:last])
    return bodies


def _own_paths_and_calls(bodies: dict[str, str]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """`(paths each function names, functions each function calls)`."""
    names = set(bodies)
    own: dict[str, set[str]] = {}
    calls: dict[str, set[str]] = {}
    for name, body in bodies.items():
        commands = shell_commands(body)
        own[name] = registry_paths(commands)
        words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", " ".join(c.executed for c in commands)))
        calls[name] = (words & names) - {name}
    return own, calls


def _reached_functions(root: str, calls: dict[str, set[str]]) -> set[str]:
    """Every function `root` reaches, itself included, transitively."""
    reached: set[str] = set()
    todo = [root]
    while todo:
        name = todo.pop()
        if name not in reached:
            reached.add(name)
            todo.extend(calls.get(name, ()))
    return reached


def local_gate_stages(text: str) -> dict[str, set[int]]:
    """For each path `local_gate.sh` names, the stages that reach it.

    A stage is a `run` line's function; it reaches every function it calls, transitively,
    and a path belongs to every stage that reaches the function naming it. A function ends
    at the first line that starts with `}`, which is how this file closes every one.
    """
    own, calls = _own_paths_and_calls(_function_bodies(text))
    stages: dict[str, set[int]] = {}
    for number, root in enumerate(STAGE.findall(text), 1):
        for name in _reached_functions(root, calls):
            for path in own.get(name, ()):
                stages.setdefault(path, set()).add(number)
    return stages


def workflow_jobs(flows: list[Workflow]) -> dict[str, set[str]]:
    """For each path a workflow names, every `<workflow file>:<job key>` naming it."""
    jobs: dict[str, set[str]] = {}
    for workflow in flows:
        name = Path(workflow.path).name
        for key, job in workflow.jobs.items():
            for path in registry_paths(job.commands()):
                jobs.setdefault(path, set()).add(f"{name}:{key}")
    return jobs
