# SPDX-License-Identifier: Apache-2.0
"""What `verification.yml`, the complete run, is allowed to be started by and to contain."""

from __future__ import annotations

from _verification_trigger.config import COMPLETE_EVENTS
from _verification_trigger.reading import parse


def _trigger_set_failures(workflow) -> list[str]:
    failures: list[str] = []
    extra = sorted(set(workflow.triggers) - COMPLETE_EVENTS)
    missing = sorted(COMPLETE_EVENTS - set(workflow.triggers))
    if extra:
        failures.append(
            f"verification.yml declares {extra}: only `schedule` and `workflow_dispatch` may "
            "start the complete run, and an ordinary pull request or push never does"
        )
    if missing:
        failures.append(f"verification.yml no longer declares {missing}: the complete run needs both")
    failures += [
        f"verification.yml's `{trigger.name}` carries a path filter: a complete run is not "
        "started by what a change touches"
        for trigger in workflow.triggers.values()
        if trigger.filtered
    ]
    return failures


def _unscoped_failures(workflow) -> list[str]:
    commands = " ".join(command.text for command in workflow.commands())
    if "select-units" not in commands:
        return []
    return [
        "verification.yml invokes `select-units`: it scopes a run to a change, and a scope "
        "that cannot be trusted must be deferred, not widened"
    ]


def _scope_guard_failures(workflow) -> list[str]:
    guard = workflow.jobs.get("scope")
    refusal = "\n".join(step.run.value for step in guard.steps if step.run) if guard else ""
    if "exit 1" in refusal and "schedule|workflow_dispatch" in refusal:
        return []
    return [
        "verification.yml's `scope` job does not refuse every event but schedule and "
        "dispatch — a trigger added by mistake would measure instead of failing"
    ]


def _aggregate_failures(workflow) -> list[str]:
    aggregate = workflow.jobs.get("aggregate")
    if aggregate is not None and "--aggregate --gate" in " ".join(c.text for c in aggregate.commands()):
        return []
    return [
        "verification.yml's `aggregate` job does not run `verify --aggregate --gate`: the "
        "step that reports a missing record as INCOMPLETE is gone"
    ]


def check_complete_run(text: str) -> list[str]:
    workflow = parse(text)
    return (
        _trigger_set_failures(workflow)
        + _unscoped_failures(workflow)
        + _scope_guard_failures(workflow)
        + _aggregate_failures(workflow)
    )
