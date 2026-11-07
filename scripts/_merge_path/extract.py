# SPDX-License-Identifier: Apache-2.0
"""Reading paths out of shell commands: what a workflow or `local_gate.sh` names, and what
it runs as a program."""

from __future__ import annotations

import os
from pathlib import Path

from _merge_path.config import ENTRY_ROOT, REPO, SHALLOW_FETCH
from workflow_reader import Command, Workflow, named_paths, shell_commands


def scripts_in(commands: list[Command]) -> set[str]:
    """The `.py`/`.sh` repository scripts these commands invoke, in any argument position.

    Commands, not text: the reader has dropped comments and usage lines, so a script a
    comment explains is not a script a step runs.
    """
    return {
        path
        for command in commands
        for path in named_paths(command.executed)
        if path.endswith((".py", ".sh"))
    }


def invoked_by(path: Path) -> set[str]:
    return scripts_in(shell_commands(path.read_text(encoding="utf-8")))


def names_in(commands: list[Command]) -> set[str]:
    """Every `tools/verification/` entry point these commands name, extension or not.

    Distinct from `scripts_in`, which is anchored on `.py`/`.sh` and so cannot see
    `verify-tests`, and from `command_position_paths`, which asks whether a path runs AS
    A PROGRAM. Neither answers *does a workflow name this control*.
    """
    return {
        path
        for command in commands
        for path in named_paths(command.executed)
        if path.startswith(f"{ENTRY_ROOT}/")
    }


def registry_paths(commands: list[Command]) -> set[str]:
    """Every path these commands name that a registry row can describe: a `.py`/`.sh`
    script anywhere, or an assurance-platform entry point."""
    return scripts_in(commands) | names_in(commands)


def _program_paths(invocation) -> set[str]:
    """The repository paths one invocation runs as a program."""
    found: set[str] = set()
    if invocation.interpreter is None and invocation.program.startswith(("scripts/", "tools/")):
        found.add(invocation.program)
    # A `./`-qualified path handed to another program is one that program runs:
    # `docker run … "$image" ./tools/verification/regenerate-lean`, `xargs ./x`.
    found |= {
        arg[2:]
        for arg in (a.strip("\"'") for a in invocation.args)
        if arg.startswith(("./scripts/", "./tools/"))
    }
    return found


def command_position_paths(commands: list[Command]) -> set[str]:
    """Every repository path these commands run AS A PROGRAM.

    A path handed to an interpreter (`python3 x.py`, `bash x.sh`, `. x.sh`) is an
    ARGUMENT, and an argument needs no execute bit; demanding one would make the gate ask
    for a property the invocation does not use. A path at the head of a command segment is
    a program, and needs one; so does a `./`-qualified path handed to a program that runs
    it.
    """
    found: set[str] = set()
    for command in commands:
        for invocation in command.invocations():
            found |= _program_paths(invocation)
    return found


def truncating_fetches(workflow: Workflow) -> list[str]:
    """Shallow fetches in a job whose checkout asked for the full history.

    Per job: the two facts are a `fetch-depth: 0` on one of the job's steps and a `--depth`
    fetch among its commands. Another job's shallow fetch does not truncate this job's
    clone.
    """
    return [
        command.text
        for job in workflow.jobs.values()
        if any(step.with_.get("fetch-depth") == "0" for step in job.steps)
        for command in job.commands()
        if SHALLOW_FETCH.search(command.text)
    ]


def not_executable(paths: set[str]) -> list[str]:
    """Those of `paths` that exist in the tree and are not executable.

    The FILESYSTEM bit, which is what a fresh clone and a CI checkout both get from the
    index — so a developer who ran `chmod +x` locally and never staged the mode change sees
    a green gate here and a red one in CI. A path that does not exist is not this gate's
    finding: the coverage half already refuses a control nothing can run, and reporting a
    missing file as a permissions defect would send someone to the wrong fix.
    """
    return sorted(
        path
        for path in paths
        if (REPO / path).is_file() and not os.access(REPO / path, os.X_OK)
    )
