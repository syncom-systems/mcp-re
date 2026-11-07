# SPDX-License-Identifier: Apache-2.0
"""The gate's commands: the static verdict, `--collect` and `--compare`."""

from __future__ import annotations

import json
from pathlib import Path

import _controls

from _test_inventory.collect import collect
from _test_inventory.compare import compare
from _test_inventory.config import ALLOWED, REPO
from _test_inventory.static import count_tests, static_gaps, tracked_rust_files


def _collect_command(path: str) -> int:
    data = collect()
    Path(path).write_text(json.dumps(data, indent=1))
    print(f"wrote {path}: {sum(len(b['tests']) for b in data['binaries'])} listed test(s)")
    return 0


def _compare_command(path: str) -> int:
    problems, report = compare(json.loads(Path(path).read_text()), _controls.rust_controls()
                               + _controls.doctest_controls(), ALLOWED)
    print("\n".join(report))
    if problems:
        print(f"test-inventory gate: FAIL — {len(problems)} problem(s)")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("test-inventory gate: OK — every reachable test is compiled into a binary "
          "`bazel test //...` runs, or into a named lane's `manual` target")
    return 0


def _static_command() -> int:
    carriers = {c.carrier for c in _controls.rust_controls()}
    files = {f: (REPO / f).read_text(errors="replace") for f in tracked_rust_files()}
    gaps = static_gaps(files, carriers)
    total = sum(count_tests(t) for t in files.values())
    if gaps:
        print(f"test-inventory gate: FAIL — {len(gaps)} file(s)")
        for g in gaps:
            print(f"  - {g}")
        return 1
    if not total:
        print("test-inventory gate: FAIL — no test found in the tree; the scan read nothing")
        return 1
    print(f"test-inventory gate: OK — {total} test(s) in {sum(1 for t in files.values() if count_tests(t))} "
          f"file(s), every file reachable from a crate root a Bazel `rust_test` compiles")
    return 0


def run(argv: list[str], usage: str) -> int:
    if len(argv) == 2 and argv[0] == "--collect":
        return _collect_command(argv[1])
    if len(argv) == 2 and argv[0] == "--compare":
        return _compare_command(argv[1])
    if argv:
        print(usage)
        return 2
    return _static_command()
