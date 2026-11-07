#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Workflow reader — the one reader of `.github/workflows/*.yml`, and of the shell commands
those workflows and the repository's scripts run.

THE FAILURE CLASS: a gate that reads a workflow with a private line regex answers a question
about the regex, not the workflow. Ten gates did, and each rediscovered the same quirks
separately or not at all. One parser ended a `paths:` list at a comment. One counted a
script named in a comment as a job that runs it. One read every two-space key under `on:`
as a job. One skipped a command whose line ended in `\\`. Each gate's own property was
right, and each gate measured something narrower or wider than it claimed.

So this module owns the syntax, and a gate states only its own property:

  * `read(path)` / `parse(text)` give a `Workflow`. It has `triggers`, each with its path
    filter or none, and `jobs`, each with the check name GitHub reports and its steps.
  * `shell_commands(text)` gives the logical commands of a `run:` body or a shell script.
    Comment lines and trailing comments are dropped and `\\` continuations are joined.
    A segment that prints (`echo`, `printf`) names a command without running it:
    `Command.executed_segments()` is the command without its printing segments, and
    `Command.prints` marks a command that only prints. `echo "$T" | docker login …` still runs `docker`.
  * `Command.invocations()` gives what each non-printing segment of a command runs: the
    program, or the script an interpreter is handed. `named_paths` gives every repository path a command
    names in any position.
  * `glob_matches` is GitHub's path-filter matching.

It is stdlib only. The YAML read is the subset these workflows use: block mappings and
sequences, `|`/`>` block scalars, flow sequences, quoted and plain scalars, and comments.
Anything outside that subset (an anchor, an alias, a merge key, a flow mapping with
content, a block scalar header with an indentation indicator, a repeated key) raises `WorkflowSyntaxError` rather than being read wrongly. A reader that guesses
is the defect this module exists to remove.

Run:  python3 scripts/workflow_reader.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

from _workflow.globs import glob_matches
from _workflow.invocation import INTERPRETERS, Invocation
from _workflow.model import WORKFLOWS, Job, Step, Trigger, Workflow, parse, read, workflows
from _workflow.selftest import selftest
from _workflow.shell import Command, named_paths, shell_commands
from _workflow.syntax import Mapping, Scalar, Sequence, WorkflowSyntaxError, parse_yaml

__all__ = [
    "INTERPRETERS",
    "WORKFLOWS",
    "Command",
    "Invocation",
    "Job",
    "Mapping",
    "Scalar",
    "Sequence",
    "Step",
    "Trigger",
    "Workflow",
    "WorkflowSyntaxError",
    "glob_matches",
    "named_paths",
    "parse",
    "parse_yaml",
    "read",
    "shell_commands",
    "workflows",
]


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    root = Path(__file__).resolve().parent.parent
    read_all = workflows(root)
    if not read_all:
        print("workflow reader: FAILED — no workflow under .github/workflows")
        return 1
    commands = sum(len(w.commands()) for w in read_all)
    print(f"workflow reader: OK — {len(read_all)} workflow(s), "
          f"{sum(len(w.jobs) for w in read_all)} job(s), {commands} command(s) read")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
