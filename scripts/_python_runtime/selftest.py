# SPDX-License-Identifier: Apache-2.0
"""The gate's selftest: every refusal is shown, and every acceptance it must not swallow."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from itertools import chain

from _python_runtime.claim import check
from _python_runtime.config import REPO_ROOT
from _python_runtime.images import check_images
from _python_runtime.selftest_cases import (
    IMAGE_SELFTEST_CASES,
    IMAGE_SELFTEST_PIN,
    SELFTEST_CASES,
    TOOLING_SELFTEST_CASES,
    WHEEL_SELFTEST_CASES,
    WHEEL_SELFTEST_PROJECT,
)
from _python_runtime.tooling import ToolingInputs, check_tooling
from _python_runtime.wheel import check_wheel_metadata

Outcome = tuple[str, bool, bool]


def _tooling_outcomes() -> Iterator[Outcome]:
    for name, tooling, module_text, flows, must_refuse in TOOLING_SELFTEST_CASES:
        inputs = ToolingInputs(tooling, module_text, flows)
        refusal = check_tooling(inputs, IMAGE_SELFTEST_PIN, REPO_ROOT)
        yield name, refusal is not None, must_refuse


def _image_outcomes() -> Iterator[Outcome]:
    for name, files, must_refuse in IMAGE_SELFTEST_CASES:
        yield name, check_images(files, IMAGE_SELFTEST_PIN) is not None, must_refuse


def _claim_outcomes() -> Iterator[Outcome]:
    for name, specifier, entry, must_refuse in SELFTEST_CASES:
        refusal, _ = check(specifier, entry)
        yield name, refusal is not None, must_refuse


def _wheel_outcomes() -> Iterator[Outcome]:
    for name, text, must_refuse in WHEEL_SELFTEST_CASES:
        yield name, check_wheel_metadata(text, WHEEL_SELFTEST_PROJECT) is not None, must_refuse


def _report(outcome: Outcome) -> bool:
    name, refused, must_refuse = outcome
    if refused != must_refuse:
        verb = "was accepted" if must_refuse else "was refused"
        print(f"  SELFTEST FAIL: {name} {verb}", file=sys.stderr)
        return False
    print(f"  ok   {name}: {'refused' if refused else 'accepted'}")
    return True


def selftest() -> int:
    outcomes = chain(_tooling_outcomes(), _image_outcomes(), _claim_outcomes(), _wheel_outcomes())
    failures = [_report(outcome) for outcome in outcomes].count(False)
    if failures:
        print(f"python-runtime gate: SELFTEST FAIL — {failures} case(s)", file=sys.stderr)
        return 1
    total = (len(SELFTEST_CASES) + len(IMAGE_SELFTEST_CASES) + len(WHEEL_SELFTEST_CASES)
             + len(TOOLING_SELFTEST_CASES))
    print(f"python-runtime gate: SELFTEST OK — {total} case(s)")
    return 0
