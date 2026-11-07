# SPDX-License-Identifier: Apache-2.0
"""Cargo invocations in a CI workflow: the commands its steps run and the actions that drive Cargo."""

from __future__ import annotations

from workflow_reader import WorkflowSyntaxError, parse

from _no_cargo.config import CARGO_ACTION, Hit
from _no_cargo.shell import shell_hits


def workflow_hits(text: str) -> list[Hit]:
    """Every command a workflow's steps run, and every action that drives Cargo.

    The commands come from the workflow reader, so a step's `name:`, a comment and a usage
    line are not commands, and a command continued across lines is one. A workflow the
    reader cannot read is a hit: a file this gate cannot see into is not one it may pass.
    """
    try:
        workflow = parse(text)
    except WorkflowSyntaxError as exc:
        return [(0, "unreadable workflow", str(exc))]
    out = [
        (command.line, rule, line)
        for command in workflow.commands()
        for _n, rule, line in shell_hits(command.code)
    ]
    out += [
        (step.line, "cargo action", step.uses)
        for job in workflow.jobs.values()
        for step in job.steps
        if step.uses and CARGO_ACTION.match(step.uses)
    ]
    return out
