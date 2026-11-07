"""The gate's real run: load the manifest and register, apply the rules, report."""

from __future__ import annotations

import sys

import _ratchet
from _unit_closure.config import REGISTER_REL, REPO, exclusions
from _unit_closure.register import (
    check_new_debt,
    check_register,
    check_transitions,
    empty_scope_is_failure,
    introduced_paths,
    validate_register,
)
from _unit_closure.rules import expansion_disagreements, flag


def _fail(message: str) -> int:
    print(f"unit-closure gate: FAIL — {message}", file=sys.stderr)
    return 1


def _against_base(reg, register: dict[str, dict]) -> list[str]:
    """The lifecycle and UC-3 problems of `register` judged against the register at BASE."""
    baseline = reg.at(_ratchet.BASE)
    if isinstance(baseline, _ratchet.Unreadable):
        return [_ratchet.unreadable_problem(REGISTER_REL, _ratchet.BASE, baseline)]
    previous = baseline.entries if isinstance(baseline, _ratchet.Present) else {}
    new_paths = introduced_paths(previous)
    if new_paths is None:
        return check_transitions(previous, register) + [
            f"UC-3: baseline unreadable — `git diff {_ratchet.BASE}...HEAD` failed, so no "
            f"path could be told apart as new. Fetch {_ratchet.BASE} and re-run"
        ]
    return check_transitions(previous, register) + check_new_debt(register, new_paths)


def _report_problems(problems: list[str]) -> int:
    print(f"unit-closure gate: FAIL — {len(problems)} problem(s)", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    print(
        "\nUC-1: a `mod` declared by a measured file must itself be measured. "
        "UC-2: so must the parent that declares a measured file, when it holds items "
        "of its own. UC-3: a path this change introduced joins a unit, never the "
        "register.",
        file=sys.stderr,
    )
    return 1


def _report_ok(units: list, walked: int, register: dict[str, dict]) -> int:
    def with_status(name: str) -> int:
        return sum(1 for e in register.values() if e.get("status") == name)

    print(
        f"unit-closure gate: OK — {len(units)} unit(s), {walked} file(s) walked through "
        f"their `mod` declarations. Register: {len(register)} path(s) outside every "
        f"closure — {with_status('unreviewed')} unreviewed, "
        f"{with_status('reviewed-attached')} reviewed-attached, "
        f"{with_status('reviewed-out-of-cone')} reviewed-out-of-cone. No unanswered "
        f"neighbour. Dispositions and UC-3 checked against {_ratchet.BASE}."
    )
    return 0


def run() -> int:
    from _manifest import ManifestError, load_verification  # noqa: PLC0415

    try:
        units = load_verification()["unit"]
    except ManifestError as exc:
        return _fail(str(exc))

    reg = exclusions()
    try:
        register = reg.current()
    except _ratchet.RegisterError as exc:
        return _fail(str(exc))
    findings, walked = flag(REPO, units)

    if empty_scope_is_failure(len(units), walked):
        return _fail(
            f"{len(units)} unit(s), {walked} file(s) walked. A "
            f"gate whose subject list is empty reports success by measuring nothing."
        )

    problems = (
        expansion_disagreements(REPO, units)
        + validate_register(register, REPO)
        + check_register(findings, register)
        + _against_base(reg, register)
    )
    if problems:
        return _report_problems(problems)
    return _report_ok(units, walked, register)
