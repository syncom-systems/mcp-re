# SPDX-License-Identifier: Apache-2.0
"""Prove each rule of the ratchet can FAIL, without building anything."""

from __future__ import annotations

import tempfile
from pathlib import Path

import _rust_targets

from _clippy_ratchet.allow import allow_discipline
from _clippy_ratchet.registry import compare
from _clippy_ratchet.selftest_cases import (
    ALLOW_CASES,
    BASELINE,
    COMPARE_CASES,
    PROJECTION_FIXTURE,
)


def _compare_failure() -> str | None:
    for counts, needle, failure in COMPARE_CASES:
        problems = compare(counts, BASELINE)
        wrong = bool(problems) if needle is None else not any(needle in p for p in problems)
        if wrong:
            return failure
    return None


def _projection_failure() -> str | None:
    # The measured targets are the table's shipping rows: a test-only flavor, a manual
    # probe and a test binary are not production code.
    projected = _rust_targets.production_targets(PROJECTION_FIXTURE)
    if projected != ["//a:a", "//a:cli"]:
        return f"the production projection is {projected}, not the two shipping rows"
    return None


def _allow_case_failure(root: Path, source: str, needle: str | None, failure: str) -> str | None:
    (root / "probe" / "src" / "lib.rs").write_text(source)
    problems = allow_discipline(root)[0]
    wrong = bool(problems) if needle is None else not any(needle in p for p in problems)
    return failure.format(problems=problems) if wrong else None


def _allow_failure() -> str | None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "probe" / "src").mkdir(parents=True)
        for source, needle, failure in ALLOW_CASES:
            message = _allow_case_failure(root, source, needle, failure)
            if message:
                return message
        # An empty scan must not read as clean.
        if allow_discipline(root / "nonexistent")[1] != 0:
            return "empty scan reported files"
    return None


def selftest() -> int:
    for check in (_compare_failure, _projection_failure, _allow_failure):
        failure = check()
        if failure:
            print(f"selftest FAIL: {failure}")
            return 1
    print("clippy-ratchet gate selftest: PASS (at-baseline, growth, improvement, "
          "deny-at-zero for unbaselined and for unwrap_used, unadopted lint ignored; "
          "production targets are the table's shipping rows; "
          "allow discipline: crate-wide, module-scoped, unjustified, both justified forms, "
          "unadopted lint, empty scan)")
    return 0
