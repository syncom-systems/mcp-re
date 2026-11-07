# SPDX-License-Identifier: Apache-2.0
"""A gate whose only evidence is that a clean tree passes has never been shown to fail."""

from __future__ import annotations

import sys

from _claim_surface import selftest_mapping, selftest_movement


def selftest() -> int:
    failures = [msg for check in selftest_mapping.CHECKS if (msg := check())]
    if failures:
        print(f"SELFTEST FAIL: {failures[0]}", file=sys.stderr)
        return 1
    fixture = selftest_movement.build_fixture()
    for check in selftest_movement.CHECKS:
        message = check(fixture)
        if message:
            print(f"SELFTEST FAIL: {message}", file=sys.stderr)
            return 1
    print("claim_surface_gate selftest: OK")
    return 0
