#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test-inventory gate — every test in the source tree is compiled into a binary `bazel
test //...` runs.

A missing BUILD target, a module no crate root declares, a Bazel crate flavor without the
feature a `#[cfg(feature = ...)]` test needs, or a target tagged `manual` each make a test
disappear with every check still green. Nothing else asks: `bazel test //...` cannot report
a test it never compiled. Two halves, because they cost very different amounts:

  * STATIC (the default, no build) — every `#[test]` in a tracked first-party `.rs` file is
    reachable, through `mod` declarations, from a crate root some `rust_test` target
    compiles. A file no tested root reaches holds tests nothing will ever compile. Runs on
    the merge path.
  * COMPILED (`--collect` then `--compare`, weekly) — every reachable test is LISTED by a
    non-manual `rust_test` on its crate root, and every doctest item by its crate's
    `rust_doc_test`. A test reachable in source and absent from every binary was compiled
    out — a feature no flavor enables.

Tests are keyed as the control census keys them (`tools/verification/_controls`): the
Bazel package, the crate root, the module path. Names prove a test is compiled, not that it
does anything. A test only a `manual` target compiles is a gap unless ALLOWED names the lane
that runs it; an ALLOWED entry that matches nothing also fails.

    python3 scripts/test_inventory_gate.py                      # static
    python3 scripts/test_inventory_gate.py --collect bazel.json # build + list every binary
    python3 scripts/test_inventory_gate.py --compare bazel.json
    python3 scripts/test_inventory_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _test_inventory.config import ALLOWED, REPO, TEST_ATTR  # noqa: E402,F401
from _test_inventory.cli import run  # noqa: E402
from _test_inventory.collect import bazel, collect, doctest_items, listed  # noqa: E402,F401
from _test_inventory.compare import compare, key, matches  # noqa: E402,F401
from _test_inventory.selftest import selftest  # noqa: E402,F401
from _test_inventory.static import count_tests, static_gaps, tracked_rust_files  # noqa: E402,F401


def main(argv: list[str]) -> int:
    if argv[:1] == ["--selftest"]:
        return selftest()
    return run(argv, __doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
