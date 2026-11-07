# SPDX-License-Identifier: Apache-2.0
"""Run the gate: read every tracked file with its reader and report each Cargo invocation."""

from __future__ import annotations

from _no_cargo.classify import scan, tracked_files
from _no_cargo.config import REPO


def judge() -> int:
    files = tracked_files()
    problems = scan(files, lambda p: (REPO / p).read_text(encoding="utf-8"))
    if problems:
        print(f"no-cargo-execution gate: FAIL — {len(problems)} Cargo invocation(s)")
        for p in problems:
            print(f"  - {p}")
        print("Rust build and test execution is Bazel's. Replace each with its Bazel form.")
        return 1
    print(f"no-cargo-execution gate: OK — {len(files)} file(s) read; no workflow, script, tool, "
          f"hook, lane, container, registry or maintained command invokes Cargo")
    return 0
