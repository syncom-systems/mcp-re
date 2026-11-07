# SPDX-License-Identifier: Apache-2.0
"""The fifth fact: the repository's own tooling runs one pinned interpreter."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from workflow_reader import Job, Step, Workflow

from _python_runtime.config import (
    BAZEL_TOOLCHAIN,
    BAZEL_VERSION,
    PYTHON_WORD,
    SETUP_PYTHON,
    TOOLING_PIN,
)


def tool_runs_python(path: str, root: Path) -> bool:
    """Whether the repository file a command runs is Python, or a shell script that runs it."""
    target = root / path
    if path.endswith(".py"):
        return True
    if not target.is_file():
        return False
    text = target.read_text(encoding="utf-8", errors="replace")
    first = text.split("\n", 1)[0]
    if first.startswith("#!"):
        if "python" in first:
            return True
        if not re.search(r"\b(ba|z)?sh\b", first):
            return False
    return any(
        PYTHON_WORD.search(line.split("#", 1)[0]) for line in text.splitlines()[1:]
    )


def _runs_repository_tool(command, root: Path) -> bool:
    """Whether the command invokes a `scripts/` or `tools/` file that is Python."""
    return any(
        invocation.program.startswith(("scripts/", "tools/")) and tool_runs_python(invocation.program, root)
        for invocation in command.invocations()
    )


def step_runs_python(step: Step, root: Path) -> bool:
    return any(
        PYTHON_WORD.search(command.executed) or _runs_repository_tool(command, root)
        for command in step.commands()
    )


def setup_reads_pin(step: Step) -> bool:
    """The step reads the pin file, at the root of the repository or of a checkout `path:`."""
    named = step.with_.get("python-version-file", "")
    return (named == TOOLING_PIN or named.endswith("/" + TOOLING_PIN)) and "python-version" not in step.with_


def _floating_setup(path: str, job: Job, step: Step) -> str:
    return (
        f"{path} job {job.key!r} line {step.line}: setup-python names its version "
        f"{step.with_!r} instead of reading `python-version-file: {TOOLING_PIN}`, "
        f"so a pin bump would leave this job behind"
    )


def _unpinned_run(path: str, job: Job, step: Step) -> str:
    return (
        f"{path} job {job.key!r} line {step.line} runs Python before any "
        f"`{SETUP_PYTHON}` step reading {TOOLING_PIN}, so it runs the runner "
        f"image's system interpreter, not the pinned one"
    )


def check_job(path: str, job: Job, root: Path) -> str | None:
    """A job that runs Python sets up the pinned interpreter, from the pin file, first."""
    set_up = False
    for step in job.steps:
        if step.uses and step.uses.startswith(SETUP_PYTHON):
            if not setup_reads_pin(step):
                return _floating_setup(path, job, step)
            set_up = True
        elif not set_up and step_runs_python(step, root):
            return _unpinned_run(path, job, step)
    return None


def _pin_refusal(tooling: str | None, module_text: str, allowed: list[str]) -> str | None:
    """The pin file exists, is pinned, and MODULE.bazel registers the same interpreter."""
    if tooling is None:
        return f"{TOOLING_PIN} is missing, so no tool that reads it runs a pinned interpreter"
    if tooling not in allowed:
        return f"{TOOLING_PIN} names {tooling!r}, and [python].interpreters pins {', '.join(allowed)}"
    block = BAZEL_TOOLCHAIN.search(module_text)
    bazel = BAZEL_VERSION.search(block.group(1)) if block else None
    if bazel is None:
        return "MODULE.bazel registers no python.toolchain version this gate can read"
    if bazel.group(1) != tooling:
        return (
            f"MODULE.bazel registers rules_python {bazel.group(1)!r} and {TOOLING_PIN} names "
            f"{tooling!r}: every Bazel py_test runs an interpreter the tooling does not"
        )
    return None


@dataclass(frozen=True)
class ToolingInputs:
    """What the tooling fact is judged over: the pin file's text, MODULE.bazel's text and
    the workflows."""

    tooling: str | None
    module_text: str
    flows: list[Workflow]


def check_tooling(inputs: ToolingInputs, pinned: dict, root: Path) -> str | None:
    """The fifth fact: the repository's tooling runs one pinned interpreter."""
    refusal = _pin_refusal(inputs.tooling, inputs.module_text, sorted(pinned.values()))
    if refusal is not None:
        return refusal
    if not inputs.flows:
        return "no workflow was read — checking nothing is not a pass"
    for flow in inputs.flows:
        for job in flow.jobs.values():
            refusal = check_job(flow.path, job, root)
            if refusal is not None:
                return refusal
    return None
