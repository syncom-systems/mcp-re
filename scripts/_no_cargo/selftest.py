# SPDX-License-Identifier: Apache-2.0
"""Prove each rule can FAIL: every case names a file, its text, and whether the gate must flag it."""

from __future__ import annotations

from _no_cargo.classify import scan
from _no_cargo.selftest_registry import REGISTRY_AND_DOC_CASES
from _no_cargo.selftest_shell import SHELL_CASES
from _no_cargo.selftest_source import SOURCE_CASES
from _no_cargo.selftest_workflow import WORKFLOW_AND_MANIFEST_CASES

CASES = SHELL_CASES + WORKFLOW_AND_MANIFEST_CASES + SOURCE_CASES + REGISTRY_AND_DOC_CASES


def _failure(path: str, text: str, expect: bool) -> str | None:
    found = scan([path], lambda _path: text)
    if bool(found) == expect:
        return None
    return f"{path}: {text!r} -> {found or 'nothing'}, expected {'a hit' if expect else 'none'}"


def selftest() -> int:
    failures = [msg for case in CASES if (msg := _failure(*case))]
    if failures:
        print("no-cargo-execution gate selftest: FAIL")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"no-cargo-execution gate selftest: PASS ({len(CASES)} cases)")
    return 0
