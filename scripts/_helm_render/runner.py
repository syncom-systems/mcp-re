# SPDX-License-Identifier: Apache-2.0
"""Running the gate: the text checks, then each rendered case family."""

from __future__ import annotations

import shutil
from collections.abc import Callable

from _helm_render.cases import ARGV_CASES, CASES, MANIFEST_CASES
from _helm_render.checks import TEXT_CHECKS
from _helm_render.config import CHART
from _helm_render.render import container_args, render

#: How a failed render is quoted back: the tail is where helm names the fault.
_RENDER_TAIL = 400


def _render_case_problem(case: tuple[str, dict, bool, str]) -> str:
    _, values, must_render, fragment = case
    ok, output = render(values)
    if must_render and not ok:
        return f"expected a successful render, got:\n{output.strip()[-600:]}"
    if not must_render and ok:
        return "the chart RENDERED but the guard must refuse it"
    if not must_render and fragment not in output:
        return (
            f"refused, but the message does not name the fault ({fragment!r} absent) — "
            f"it may be failing for an unrelated reason:\n{output.strip()[-400:]}"
        )
    return ""


def _pair_problems(args: list[str], required: str | tuple[str, str]) -> list[str]:
    # A bare string is a VALUELESS flag (`--gcp-kms-use-metadata`,
    # `--aws-kms-use-web-identity`): presence is the whole assertion, and
    # indexing +1 would read the next unrelated argument as its value.
    if isinstance(required, str):
        return [] if required in args else [f"{required} missing"]
    flag, value = required
    if flag not in args:
        return [f"{flag} missing"]
    actual = args[args.index(flag) + 1]
    return [] if actual == value else [f"{flag} carries {actual!r}, expected {value!r}"]


def _argv_case_problem(case: tuple[str, dict, list[tuple[str, str]], list[str]]) -> str:
    _, values, required_pairs, forbidden = case
    ok, output = render(values)
    if not ok:
        return f"render failed:\n{output.strip()[-_RENDER_TAIL:]}"
    args = container_args(output)
    problems = [p for required in required_pairs for p in _pair_problems(args, required)]
    problems += [f"{flag} present but must be omitted" for flag in forbidden if flag in args]
    return "; ".join(problems)


def _declared_lines(output: str) -> set[str]:
    """The manifest's lines, stripped, with blanks and comments dropped.

    The assertion is about what the manifest DECLARES, and every one of these fields is
    argued for in a comment right above it.
    """
    stripped = (line.strip() for line in output.splitlines())
    return {line for line in stripped if line and not line.startswith("#")}


def _manifest_case_problem(case: tuple[str, dict, list[str], list[str]]) -> str:
    _, values, required_lines, forbidden_lines = case
    ok, output = render(values)
    if not ok:
        return f"render failed:\n{output.strip()[-_RENDER_TAIL:]}"
    lines = _declared_lines(output)
    problems = [f"{line!r} missing" for line in required_lines if line not in lines]
    problems += [f"{line!r} present but must be absent" for line in forbidden_lines
                 if line in lines]
    return "; ".join(problems)


def _run_family(cases: list, problem_of: Callable[[tuple], str]) -> list[str]:
    """Run every case of one family, printing each verdict; the failures, named."""
    failures = []
    for case in cases:
        name, problem = case[0], problem_of(case)
        if problem:
            failures.append(f"{name}: {problem}")
        print(f"  {'FAIL' if problem else 'ok  '} {name}")
    return failures


def _run_text_checks() -> list[str]:
    """Image-vs-chart couplings. Neither is visible in a render: the chart can be
    perfect and the artifact still unable to run what it describes."""
    failures = []
    for label, check in TEXT_CHECKS:
        problems = check()
        failures.extend(f"{label}: {p}" for p in problems)
        print(f"  {'FAIL' if problems else 'ok  '} {label}")
    return failures


def run_gate() -> int:
    if shutil.which("helm") is None:
        print("FAIL: helm not found on PATH; this gate cannot verify the chart guards")
        return 2
    if not CHART.is_dir():
        print(f"FAIL: chart not found at {CHART}")
        return 2

    failures = _run_text_checks()
    failures += _run_family(CASES, _render_case_problem)
    failures += _run_family(ARGV_CASES, _argv_case_problem)
    failures += _run_family(MANIFEST_CASES, _manifest_case_problem)

    if failures:
        print("\nhelm render gate FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"\nhelm render gate: {4 + len(CASES) + len(ARGV_CASES) + len(MANIFEST_CASES)} cases pass")
    return 0
