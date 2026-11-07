# SPDX-License-Identifier: Apache-2.0
"""INVOCATION: the release workflow calls the canonical command, in command position."""

from __future__ import annotations

from workflow_reader import WorkflowSyntaxError, parse

from _release_assurance.config import CANONICAL, WORKFLOW


def invoked(text: str, target: str) -> bool:
    """Does this workflow CALL `target`, rather than mention it?

    A call is `target` run by a step: as the program of a command segment, or as the script
    an interpreter runs, after any environment assignments. The workflow reader gives the
    commands of `run:` steps only, without comments: a step's `name:`, an action's `with:`
    input and a comment are VALUES or prose, and naming the path there runs nothing.
    """
    return any(
        invocation.program == target
        for command in parse(text).commands()
        for invocation in command.invocations()
    )


def invocation_problems(read: dict[str, str]) -> list[str]:
    """The release workflow calls the canonical command."""
    text = read.get(str(WORKFLOW))
    if text is None:
        return [
            f"{WORKFLOW} does not exist. The canonical command `{CANONICAL}` would then "
            "have no caller, which is the state this gate exists to make impossible."
        ]
    try:
        called = invoked(text, CANONICAL)
    except WorkflowSyntaxError as exc:
        return [f"{WORKFLOW} cannot be read, so its caller cannot be established: {exc}"]
    if called:
        return []
    return [
        f"{WORKFLOW} does not invoke `{CANONICAL}` in command position. It may name it "
        "in a comment or a step name; a mention is not a caller, and this gate's own "
        "docstring names the same path."
    ]
