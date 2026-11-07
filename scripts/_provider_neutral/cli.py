# SPDX-License-Identifier: Apache-2.0
"""Run the gate over the repository and report each finding in the local closure."""

from __future__ import annotations

from _provider_neutral.closure import adjudicate, read_repo
from _provider_neutral.config import ENTRY


def judge() -> int:
    closure, problems = adjudicate(read_repo())
    for problem in problems:
        print(f"  ✗ {problem}")
    if problems:
        print(f"provider-neutral closure gate: FAILED ({len(problems)} finding(s) in the local execution closure)")
        return 1
    print(f"provider-neutral closure gate: OK — {len(closure)} script(s) reachable from {ENTRY}, "
          f"none invoking a provider CLI, credential or registry")
    return 0
