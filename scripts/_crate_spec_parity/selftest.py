# SPDX-License-Identifier: Apache-2.0
"""Every case asserted in BOTH directions: a gate that always fails passes the failing
half of a probe, and a gate that never fires passes the passing half."""

from __future__ import annotations

from _crate_spec_parity.compare import compare, repin_inputs
from _crate_spec_parity.selftest_fixtures import (
    CARGO_LOCK,
    META,
    REPIN_CASES,
    SPEC_CASES,
    SpecCase,
)


def _spec_failure(case: SpecCase) -> str | None:
    problems, _, _ = compare(META, case.module, case.lock, CARGO_LOCK)
    text = "\n".join(problems)
    if case.expect is None and problems:
        return f"SELFTEST FAILED: {case.label}: reported {problems}"
    if case.expect is not None and case.expect not in text:
        return (
            f"SELFTEST FAILED: {case.label}: expected a problem naming {case.expect!r}, "
            f"got {problems}"
        )
    return None


def _repin_wrong(expect: str | None, text: str) -> bool:
    """A clean lock must report nothing; any other must report a problem naming `expect`."""
    if expect is None:
        return bool(text)
    return not text or expect not in text


def _repin_failure(label: str, lock_text: str, expect: str | None) -> str | None:
    text = "\n".join(repin_inputs(lock_text))
    if _repin_wrong(expect, text):
        return f"SELFTEST FAILED: {label}: reported {text!r}"
    return None


def _first_failure() -> str | None:
    failures = [_spec_failure(case) for case in SPEC_CASES]
    failures += [_repin_failure(*case) for case in REPIN_CASES]
    return next((f for f in failures if f), None)


def selftest() -> int:
    failure = _first_failure()
    if failure:
        print(failure)
        return 1
    print(f"crate-spec parity gate selftest: PASS ({len(SPEC_CASES) + len(REPIN_CASES)} cases)")
    return 0
