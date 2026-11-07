# SPDX-License-Identifier: Apache-2.0
"""The gate's verdict on the real tree."""

from __future__ import annotations

import sys

from _bazel_srcs.config import REPO, TARGET_TABLE
from _bazel_srcs.libraries import check_libraries
from _bazel_srcs.source_trees import check_source_trees


def _fail(findings: list[str]) -> int:
    print("bazel srcs gate: FAIL", file=sys.stderr)
    for f in findings:
        print(f"  {f}", file=sys.stderr)
    print(
        "\nA hand list drifts silently: the module tree moves, the list does not. Add the "
        "file or the package to the list.",
        file=sys.stderr,
    )
    return 1


def judge() -> int:
    library_findings, libraries = check_libraries(REPO)
    tree_findings, tree_files = check_source_trees(REPO)
    findings = library_findings + tree_findings
    if findings:
        return _fail(findings)
    if not libraries:
        print(
            f"bazel srcs gate: FAIL — {TARGET_TABLE} holds no library target, so this gate "
            f"checked nothing; a pass here would be vacuous.",
            file=sys.stderr,
        )
        return 1
    print(
        f"bazel srcs gate: OK — the module tree of each of {libraries} library target(s) is "
        f"in its srcs; the audit-vocabulary guard's source trees carry all {tree_files} "
        f"file(s) its crates' targets compile"
    )
    return 0
