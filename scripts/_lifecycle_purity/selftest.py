# SPDX-License-Identifier: Apache-2.0
"""Prove the gate can fail, in both directions it previously got wrong."""

from __future__ import annotations

from _lifecycle_purity.dependencies import external_dependencies
from _lifecycle_purity.selftest_cases import Case, child_cases, module_cases


def _run_child(case: Case) -> bool:
    source, should_fail, label = case
    if bool(external_dependencies(source, child=True)) != should_fail:
        print(f"SELFTEST FAIL: {label} — expected {'rejection' if should_fail else 'acceptance'}")
        return False
    print(f"ok   {label}")
    return True


def _run_module(case: Case) -> bool:
    source, should_fail, label = case
    if bool(external_dependencies(source)) != should_fail:
        print(
            f"SELFTEST FAIL: {label} — expected "
            f"{'rejection' if should_fail else 'acceptance'}, got the opposite"
        )
        return False
    print(f"ok   {label}")
    return True


def selftest() -> int:
    results = [_run_child(case) for case in child_cases()]
    results += [_run_module(case) for case in module_cases()]
    failures = results.count(False)
    if failures:
        print(f"\n{failures} selftest failure(s)")
        return 1
    print("\nlifecycle_purity_gate selftest: PASS")
    return 0
