# SPDX-License-Identifier: Apache-2.0
"""The gate's verdict over the real repository."""

from __future__ import annotations

from _crate_spec_parity.compare import compare, repin_inputs
from _crate_spec_parity.config import (
    BAZEL_LOCK,
    BAZEL_ONLY_SPECS,
    FIX,
    MODULE,
    MODULE_LOCK,
    REPO,
)
from _crate_spec_parity.manifests import cargo_locks, workspace_meta


def verdict() -> int:
    problems, specs, packages = compare(
        workspace_meta(REPO), MODULE.read_text(), BAZEL_LOCK.read_text(), cargo_locks(REPO)
    )
    problems += repin_inputs(MODULE_LOCK.read_text())
    if problems:
        print(f"crate-spec parity gate: FAIL — {len(problems)} problem(s)")
        for p in problems:
            print(f"  - {p}")
        print(f"To fix: {FIX}")
        return 1
    print(
        f"crate-spec parity gate: OK — {specs} crate spec(s) match the Cargo workspace; "
        f"{packages} package(s) in bazel/crates.lock match the Cargo locks by version and checksum; "
        f"Bazel-only: {', '.join(sorted(BAZEL_ONLY_SPECS))}"
    )
    return 0
