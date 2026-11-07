# SPDX-License-Identifier: Apache-2.0
"""A workflow as its gates read it: triggers with their path filters, jobs with their steps."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from _workflow.shell import Command, shell_commands
from _workflow.syntax import Mapping, Scalar, Sequence, WorkflowSyntaxError, parse_yaml

WORKFLOWS = Path(".github") / "workflows"


def _strings(node: object) -> tuple[str, ...] | None:
    if node is None:
        return None
    if isinstance(node, Scalar):
        return (node.value,)
    if isinstance(node, Sequence):
        return tuple(item.value for item in node.items if isinstance(item, Scalar))
    raise WorkflowSyntaxError("expected a scalar or a sequence of scalars")


def _text(node: object, default: str | None = None) -> str | None:
    """The text of a scalar node, or `default` for any other node."""
    return node.value if isinstance(node, Scalar) else default


@dataclass(frozen=True)
class Trigger:
    name: str
    #: `None` when the trigger has no `paths:` filter: then every change starts it.
    paths: tuple[str, ...] | None
    paths_ignore: tuple[str, ...] | None

    @property
    def filtered(self) -> bool:
        """Does this trigger start on only some changes?"""
        return self.paths is not None or self.paths_ignore is not None


def _run_commands(run: Scalar) -> list[Command]:
    """The commands of a `run:` scalar, numbered by the line each sits on."""
    if run.style and not run.lines:
        return []
    if run.style == "|":
        return shell_commands("\n".join(text for _n, text in run.lines), run.lines[0][0])
    if run.style == ">":
        return shell_commands(run.value, run.lines[0][0])
    return shell_commands(run.value, run.line)


@dataclass(frozen=True)
class Step:
    line: int
    name: str | None
    uses: str | None
    run: Scalar | None
    with_: dict[str, str]

    def commands(self) -> list[Command]:
        return [] if self.run is None else _run_commands(self.run)


@dataclass(frozen=True)
class Job:
    key: str
    #: The check name GitHub reports: the job's `name:`, or its key when it has none.
    name: str
    line: int
    runs_on: tuple[str, ...]
    steps: tuple[Step, ...]

    def commands(self) -> list[Command]:
        return [command for step in self.steps for command in step.commands()]


@dataclass(frozen=True)
class Workflow:
    path: str
    triggers: dict[str, Trigger]
    jobs: dict[str, Job]

    def commands(self) -> list[Command]:
        return [command for job in self.jobs.values() for command in job.commands()]


def _trigger(name: str, body: object) -> Trigger:
    if isinstance(body, Mapping):
        return Trigger(name, _strings(body.get("paths")), _strings(body.get("paths-ignore")))
    return Trigger(name, None, None)


def _triggers(node: object) -> dict[str, Trigger]:
    if node is None:
        return {}
    if isinstance(node, Scalar):
        return {node.value: Trigger(node.value, None, None)}
    if isinstance(node, Sequence):
        return {item.value: Trigger(item.value, None, None) for item in node.items if isinstance(item, Scalar)}
    if not isinstance(node, Mapping):
        raise WorkflowSyntaxError("`on:` is neither a name, a list nor a mapping")
    return {name: _trigger(name, body) for name, body in node.items.items()}


def _with_values(node: object) -> dict[str, str]:
    if not isinstance(node, Mapping):
        return {}
    return {key: value.value for key, value in node.items.items() if isinstance(value, Scalar)}


def _step(node: object) -> Step:
    if not isinstance(node, Mapping):
        raise WorkflowSyntaxError("a step is not a mapping")
    run = node.get("run")
    if run is not None and not isinstance(run, Scalar):
        raise WorkflowSyntaxError(f"line {node.line}: `run:` is not a scalar")
    return Step(node.line, _text(node.get("name")), _text(node.get("uses")), run, _with_values(node.get("with")))


def _job(key: str, body: object, line: int) -> Job:
    if not isinstance(body, Mapping):
        raise WorkflowSyntaxError(f"job `{key}` is not a mapping")
    steps = body.get("steps")
    return Job(
        key,
        _text(body.get("name"), key) or "",
        line,
        _strings(body.get("runs-on")) or (),
        tuple(_step(s) for s in steps.items) if isinstance(steps, Sequence) else (),
    )


def _jobs(node: object) -> dict[str, Job]:
    if node is None:
        return {}
    if not isinstance(node, Mapping):
        raise WorkflowSyntaxError("`jobs:` is not a mapping")
    return {key: _job(key, body, node.key_lines[key]) for key, body in node.items.items()}


def parse(text: str, path: str = "<text>") -> Workflow:
    top = parse_yaml(text)
    return Workflow(path, _triggers(top.get("on")), _jobs(top.get("jobs")))


def read(path: Path) -> Workflow:
    return parse(path.read_text(encoding="utf-8"), str(path))


def workflows(root: Path) -> list[Workflow]:
    """Every workflow under `root`, in name order."""
    return [read(path) for path in sorted((root / WORKFLOWS).glob("*.yml"))]
