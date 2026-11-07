# SPDX-License-Identifier: Apache-2.0
"""Which checks a lane requires, derived from the lane catalogue and the workflows."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from _merge_readiness.errors import Undecidable
from _merge_readiness.paths import REPO
from workflow_reader import glob_matches, named_paths, read

from _evidence import MALFORMED_LANE  # noqa: E402
from _lanes import LANES  # noqa: E402

#: Where the workflows are read from. Replaced only by `workflows_dir`.
WORKFLOWS = REPO / ".github" / "workflows"

#: The umbrella that runs every lane in one invocation. A job naming it satisfies every
#: lane's requirement, which is why the mapping cannot be read off lane scripts alone.
UMBRELLA = "tools/verification/verify"


@contextmanager
def workflows_dir(path: Path) -> Iterator[None]:
    """Read the workflows from `path` for the duration of the block."""
    global WORKFLOWS
    saved, WORKFLOWS = WORKFLOWS, path
    try:
        yield
    finally:
        WORKFLOWS = saved


def lane_scripts() -> dict[str, str]:
    """`{lane: script}` from the lane catalogue the umbrella runs — the naming authority."""
    return {lane.name: lane.script for lane in LANES}


def workflow_jobs() -> list[tuple[str, str, set[str]]]:
    """`(workflow, check name, scripts that job invokes)` for every job in every workflow.

    The check name is the job's `name:`, because that is the string GitHub reports and
    therefore the only one a readiness query can match on; a job without one is reported
    under its key. A lane whose job cannot be named fails loudly below rather than
    resolving to nothing.

    COUNT INVOCATIONS, NOT MENTIONS. The scripts are read from the job's commands, which the
    workflow reader gives without comments, trailing comments or usage lines. These
    workflows are heavily commented, and explaining why a step exists means naming what it
    runs: a comment in `ci.yml` reading "`tools/verification/verify --manifests` fails on the
    same fact" once made the CARGO job look like it invoked the umbrella.

    A name carrying an expression (`mutation probe shard ${{ matrix.shard }}`) is a template,
    not a check name: GitHub reports one check per expansion, and none of them is the string
    the workflow states. Such a job is a shard whose lane is carried by the job that composes
    its shards, so it is not returned; were it returned, a deferral that skips the shards
    would read as a required check that is missing.
    """
    jobs: list[tuple[str, str, set[str]]] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for job in read(path).jobs.values():
            if "${{" not in job.name:
                jobs.append((path.name, job.name, _invoked(job)))
    return jobs


def _invoked(job) -> set[str]:
    """The scripts a job's commands name, never its comments."""
    return {script for command in job.commands() for script in named_paths(command.executed)}


def _matches(patterns, changed_file: str) -> bool:
    return any(glob_matches(pattern, changed_file) for pattern in patterns)


def _starts(trigger, changed: set[str]) -> bool:
    """Whether a `pull_request` trigger starts for a change touching `changed`."""
    if trigger.paths is not None:
        return any(_matches(trigger.paths, c) for c in changed)
    if trigger.paths_ignore is not None:
        return any(not _matches(trigger.paths_ignore, c) for c in changed)
    return True


def pull_request_workflows(changed: set[str]) -> set[str]:
    """The workflow files a pull request changing `changed` starts, by GitHub's rule: a
    `pull_request` trigger with no path filter, or a filter matching a changed file.

    The complete verification run is not among them (it starts only on schedule and dispatch),
    so a lane only that run executes is never a pre-merge requirement.
    """
    started: set[str] = set()
    for path in sorted(WORKFLOWS.glob("*.yml")):
        trigger = read(path).triggers.get("pull_request")
        if trigger is not None and _starts(trigger, changed):
            started.add(path.name)
    return started


def umbrella_checks() -> set[str]:
    """The check names that run the umbrella, and therefore several lanes at once.

    Kept apart from the per-lane mapping because it answers a different question: not
    "which job runs this lane" but "whose failure is attributable to one lane". Derived
    the same way, from the workflows, so a job that stops invoking the umbrella stops
    being treated as one.
    """
    return {name for _wf, name, invoked in workflow_jobs() if UMBRELLA in invoked}


def _lane_script(lane: str, scripts: dict[str, str]) -> str:
    """The script a claimed lane runs; a lane that cannot be named is `Undecidable`."""
    if lane == MALFORMED_LANE:
        raise Undecidable(
            "a unit declares an evidence entry that is not a URI, so the lane it "
            "claims cannot be named; fix the manifest before asking about a merge"
        )
    script = scripts.get(lane)
    if script is None:
        raise Undecidable(
            f"lane '{lane}' is claimed by the manifest but is not in the lane catalogue, so "
            f"no script and no job can be derived for it"
        )
    return script


def checks_for_lanes(
    lanes: set[str], scripts: dict[str, str], started: set[str] | None = None
) -> dict[str, list[str]]:
    """`{lane: [check names]}` — every job that executes each lane, from the workflows.

    `started` is the set of workflow files the change's pull request starts. A lane whose jobs
    all live in workflows that do not start has NO pre-merge check: it maps to `[]`, and the
    caller reports it as deferred to the complete run rather than as satisfied or missing.
    `None` means every workflow counts.

    A lane is run by a job invoking its own script OR the umbrella that contains it, and
    BOTH shapes exist here: `mutation` has a dedicated path-filtered job and is also inside
    the umbrella. All of them are returned rather than one picked, because any job that
    actually measured the lane at this SHA satisfies it, and choosing between them here
    would be this file inventing a policy the workflows do not state.

    Resolving to nothing raises: a required lane no workflow runs is exactly the shape that
    lets a merge proceed on evidence that never existed, and it must not read as satisfied.
    """
    jobs = workflow_jobs()
    resolved: dict[str, list[str]] = {}
    for lane in sorted(lanes):
        script = _lane_script(lane, scripts)
        wanted = {f"tools/verification/{script}", UMBRELLA}
        runners = [(wf, name) for wf, name, invoked in jobs if invoked & wanted]
        if not runners:
            raise Undecidable(
                f"lane '{lane}' (tools/verification/{script}) is required but no workflow "
                f"job invokes it or the umbrella; nothing would ever measure it"
            )
        resolved[lane] = sorted({name for wf, name in runners if started is None or wf in started})
    return resolved
