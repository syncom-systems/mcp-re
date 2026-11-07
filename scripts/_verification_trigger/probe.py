# SPDX-License-Identifier: Apache-2.0
"""What `mutation-probe.yml`, the bounded probe, must keep: its triggers, bounds and deferral."""

from __future__ import annotations

import re

from _verification_trigger.config import PROBE_EVENTS, PROBE_MAX_TIMEOUT_MINUTES, PROBE_MAX_UNITS
from _verification_trigger.reading import job_scalar, parse


def _bounded_timeout(value: str | None) -> bool:
    return value is not None and value.isdigit() and int(value) <= PROBE_MAX_TIMEOUT_MINUTES


def _trigger_failures(workflow) -> list[str]:
    failures: list[str] = []
    extra = sorted(set(workflow.triggers) - PROBE_EVENTS)
    if extra:
        failures.append(
            f"mutation-probe.yml declares {extra}: a bounded probe runs on a pull request, and "
            "the complete run is weekly or dispatched, never a push to main"
        )
    pull_request = workflow.triggers.get("pull_request")
    if pull_request is None or not pull_request.paths:
        failures.append("mutation-probe.yml's `pull_request` has no path filter: the probe starts only on what it can invalidate")
    return failures


def _timeout_failures(text: str) -> list[str]:
    failures: list[str] = []
    timeout = job_scalar(text, "probe", "timeout-minutes")
    if not _bounded_timeout(timeout):
        failures.append(
            f"mutation-probe.yml's `probe` job has timeout-minutes {timeout!r}; it must be an "
            f"integer of at most {PROBE_MAX_TIMEOUT_MINUTES}"
        )
    scope_timeout = job_scalar(text, "scope", "timeout-minutes")
    if not _bounded_timeout(scope_timeout):
        failures.append(f"mutation-probe.yml's `scope` job has timeout-minutes {scope_timeout!r}; it must be bounded")
    return failures


def _skip_on_deferral_failures(text: str) -> list[str]:
    gate = job_scalar(text, "probe", "if") or ""
    if "needs.scope.outputs.measure == 'true'" in gate and job_scalar(text, "probe", "needs") == "scope":
        return []
    return [
        "mutation-probe.yml's `probe` job does not run only when `scope` decided to measure: a "
        "deferral must SKIP the check, because a job that succeeded having applied nothing "
        "reads as a measured lane to the merge-readiness gate"
    ]


def _unit_caps(commands: list[str]) -> list[int]:
    selects = [c for c in commands if "select-units" in c]
    return [int(m.group(1)) for c in selects for m in re.finditer(r"--max-units\s+(\d+)", c)]


def _cap_failures(commands: list[str]) -> list[str]:
    caps = _unit_caps(commands)
    if caps and max(caps) <= PROBE_MAX_UNITS:
        return []
    return [
        f"mutation-probe.yml does not pass `select-units --max-units N` with N <= "
        f"{PROBE_MAX_UNITS}: an unbounded scope is a complete run in disguise"
    ]


def _deferral_failures(commands: list[str]) -> list[str]:
    if any(re.search(r"if\s+!\s+python3\s+\S*select-units", c) for c in commands):
        return []
    return [
        "mutation-probe.yml does not defer when `select-units` itself fails: a scope that "
        "cannot be computed must apply no probe, not stop the check or widen it"
    ]


def _scope_command_failures(commands: list[str]) -> list[str]:
    return _cap_failures(commands) + _deferral_failures(commands)


def _toolchain_failures(workflow, commands: list[str]) -> list[str]:
    failures = [
        f"mutation-probe.yml installs or selects a toolchain ({c.strip()[:60]!r}): every Rust "
        "member of a probe battery is a Bazel target under the compiler MODULE.bazel pins"
        for c in commands
        if re.search(r"\brustup\b|\bcargo\b", c)
    ]
    failures += [
        f"mutation-probe.yml uses `{step.uses}`, a floating toolchain installer"
        for job in workflow.jobs.values()
        for step in job.steps
        if step.uses and "rust-toolchain" in step.uses
    ]
    return failures


def check_bounded_probe(text: str) -> list[str]:
    workflow = parse(text)
    commands = [command.text for command in workflow.commands()]
    return (
        _trigger_failures(workflow)
        + _timeout_failures(text)
        + _skip_on_deferral_failures(text)
        + _scope_command_failures(commands)
        + _toolchain_failures(workflow, commands)
    )
