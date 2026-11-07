# SPDX-License-Identifier: Apache-2.0
"""The gate's selftest: a gate whose only evidence is that a clean tree passes has never
been shown to fail."""

from __future__ import annotations

import sys

from _merge_path import selftest_defects, selftest_extract, selftest_population, selftest_registry
from _merge_path.selftest_support import SelftestFailure

_GROUPS = (
    selftest_defects,
    selftest_extract,
    selftest_population,
    selftest_registry,
)


def selftest() -> int:
    try:
        for group in _GROUPS:
            group.check()
    except SelftestFailure as failure:
        print(f"SELFTEST FAIL: {failure}", file=sys.stderr)
        return 1
    print("merge_path_gate selftest: OK")
    return 0
