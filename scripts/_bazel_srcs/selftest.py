# SPDX-License-Identifier: Apache-2.0
"""The gate's selftest: each way a hand list can drift must be a finding."""

from __future__ import annotations

from _bazel_srcs.selftest_libraries import library_cases
from _bazel_srcs.selftest_trees import tree_cases


def selftest() -> int:
    libraries_ok = library_cases()
    trees_ok = tree_cases()
    if not (libraries_ok and trees_ok):
        return 1
    print("bazel srcs gate selftest: PASS")
    return 0
