# SPDX-License-Identifier: Apache-2.0
"""Merge-path starts, indirect starts, stale path filters and the negative controls."""

from __future__ import annotations

import re
from pathlib import Path

from _verification_trigger.config import CONTROL_PATHS, PLATFORM_PATHS
from _verification_trigger.reading import job_uses, parse, starts_on

VERIFICATION_CALL = "./.github/workflows/verification.yml"
DISPATCH = re.compile(r"gh\s+workflow\s+run|/dispatches\b|gh\s+api\b[^\n]*workflows")


def _pre_merge_failures(pre_merge: str) -> list[str]:
    failures: list[str] = []
    pre = parse(pre_merge)
    trigger = pre.triggers.get("pull_request")
    if trigger is None or trigger.filtered:
        failures.append("pre-merge.yml must start on EVERY pull request: no `paths` or `paths-ignore`")
    if "workflow_call" not in pre.triggers:
        failures.append("pre-merge.yml is not callable: post-merge.yml cannot run it on main")
    return failures


def _post_merge_failures(post_merge: str) -> list[str]:
    failures: list[str] = []
    post = parse(post_merge)
    push = post.triggers.get("push")
    if push is None or push.filtered:
        failures.append("post-merge.yml must start on every push to main: no path filter")
    if "pull_request" in post.triggers:
        failures.append("post-merge.yml declares `pull_request`: it is the after-merge run")
    calls = [uses for job in post.jobs.values() if (uses := job_uses(post_merge, job.key))]
    if "./.github/workflows/pre-merge.yml" not in calls:
        failures.append("post-merge.yml does not call ./.github/workflows/pre-merge.yml")
    return failures


def check_merge_path(pre_merge: str, post_merge: str) -> list[str]:
    return _pre_merge_failures(pre_merge) + _post_merge_failures(post_merge)


def _indirect_failures(name: str, text: str) -> list[str]:
    workflow = parse(text)
    failures: list[str] = []
    if "workflow_run" in workflow.triggers:
        failures.append(f"{name} declares `workflow_run`: a chained run is an indirect start")
    if name == "verification.yml":
        return failures
    failures += [
        f"{name}: job `{key}` calls verification.yml"
        for key in workflow.jobs
        if job_uses(text, key) == VERIFICATION_CALL
    ]
    failures += [
        f"{name}: dispatches a workflow ({command.text.strip()[:60]!r})"
        for command in workflow.commands()
        if DISPATCH.search(command.text)
    ]
    return failures


def check_indirect(texts: dict[str, str]) -> list[str]:
    failures: list[str] = []
    for name, text in sorted(texts.items()):
        failures += _indirect_failures(name, text)
    return failures


def stale_filters(workflow_text: str, repo: Path, required: list[str]) -> list[str]:
    """Wildcard-free `paths:` entries that name neither a file in the tree nor a fingerprint
    input. A filter that matches nothing is not a trigger; it is a claim about what re-runs
    the lane that stopped being true."""
    wanted = set(required)
    stale: list[str] = []
    for trigger in parse(workflow_text).triggers.values():
        for pattern in trigger.paths or ():
            if any(ch in pattern for ch in "*?[") or pattern in wanted:
                continue
            if not (repo / pattern).exists():
                stale.append(pattern)
    return sorted(set(stale))


def _complete_run_control_failures(verification: str) -> list[str]:
    return [
        f"a {event} changing {path} starts the complete run"
        for event in ("pull_request", "push")
        for path in CONTROL_PATHS
        if starts_on(verification, event, path)
    ]


def _probe_push_control_failures(probe: str) -> list[str]:
    return [
        f"a push changing {path} starts the mutation probe"
        for path in CONTROL_PATHS
        if not (path.startswith("tools/verification/") or path.endswith("mutation-probe.yml"))
        and starts_on(probe, "push", path)
    ]


def _platform_control_failures(deferral) -> list[str]:
    return [
        f"select-units would scope a change to {path}, a platform file, instead of deferring"
        for path in PLATFORM_PATHS
        if deferral([path]) is None
    ]


def check_controls(verification: str, probe: str, deferral) -> list[str]:
    """The negative controls, as properties of the given workflow texts."""
    return (
        _complete_run_control_failures(verification)
        + _probe_push_control_failures(probe)
        + _platform_control_failures(deferral)
    )
