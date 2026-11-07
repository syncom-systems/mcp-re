# SPDX-License-Identifier: Apache-2.0
"""The COMPILED half's comparison: reachable controls against what the binaries list."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import _rust_targets


def key(project: str, identity: str) -> str:
    return f"{project} {identity}"


def matches(name: str, pattern: str) -> bool:
    """`*` is the only wildcard."""
    return re.fullmatch(".*".join(map(re.escape, pattern.split("*"))), name) is not None


@dataclass
class Coverage:
    """The test names the binaries list: those a non-manual target covers, those only a
    `manual` one lists, and the per-binary report lines."""

    covered: set[str] = field(default_factory=set)
    manual: set[str] = field(default_factory=set)
    report: list[str] = field(default_factory=list)


def _binary_report(b: dict) -> list[str]:
    flag = " [manual]" if b["manual"] else ""
    lines = [f"  {len(b['tests']):5} tests  {b['label']}{flag}"]
    if "does_not_build" in b:
        lines.append("        does not build:\n" + "\n".join(
            "          " + line for line in b["does_not_build"].splitlines()[-8:]))
    return lines


def coverage_of(inventory: dict) -> Coverage:
    coverage = Coverage()
    for b in inventory["binaries"]:
        root = _rust_targets.root_identity(b["root"], b["package"])
        names = {key(b["package"], f"{root}#{t}") for t in b["tests"]}
        (coverage.manual if b["manual"] else coverage.covered).update(names)
        coverage.report += _binary_report(b)
    for d in inventory["doctests"]:
        coverage.covered.update(key(d["package"], f"doc#{item}") for item in d["items"])
    return coverage


def _gap_outcome(control, coverage: Coverage, allowed: dict[str, str]) -> tuple[str | None, str | None, list[str]]:
    """For an uncovered control: the problem (if no ALLOWED lane holds it), the report line (if
    one does), and the ALLOWED patterns it matched."""
    name = key(control.project, control.identity)
    hits = [p for p in allowed if matches(name, p)]
    where = "only in a `manual` target" if name in coverage.manual else "in no Bazel test binary"
    if hits:
        return None, f"  allowed: {name} ({where}) — {allowed[hits[0]]}", hits
    return (
        f"`{name}` ({control.carrier}:{control.line}) is reachable in source "
        f"and {where} — compiled out of every non-manual flavor",
        None,
        hits,
    )


def compare(inventory: dict, controls: list, allowed: dict[str, str]) -> tuple[list[str], list[str]]:
    """(problems, report lines) for the reachable controls against what the binaries list."""
    coverage = coverage_of(inventory)
    report = coverage.report
    problems: list[str] = []
    if not any(b["tests"] for b in inventory["binaries"]):
        problems.append("no binary listed a test — comparing nothing is not a pass")
    used: set[str] = set()
    gaps = 0
    for control in controls:
        if key(control.project, control.identity) in coverage.covered:
            continue
        gaps += 1
        problem, line, hits = _gap_outcome(control, coverage, allowed)
        used.update(hits)
        if problem is not None:
            problems.append(problem)
        if line is not None:
            report.append(line)
    problems += [f"ALLOWED entry `{p}` matches no gap — remove it" for p in sorted(set(allowed) - used)]
    report.append(f"{len(controls)} reachable test(s); {len(coverage.covered)} listed by non-manual "
                  f"binaries or doctest targets; {gaps} gap(s), {len(used)} allow entr(ies) used")
    return problems, report
