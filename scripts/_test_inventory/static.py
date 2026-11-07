# SPDX-License-Identifier: Apache-2.0
"""The STATIC half: every `#[test]` file is reachable from a crate root a `rust_test` compiles."""

from __future__ import annotations

import subprocess

from _test_inventory.config import REPO, TEST_ATTR


def tracked_rust_files() -> list[str]:
    # Tracked, and untracked-but-not-ignored: a test file written and not yet added is
    # exactly the one no target compiles yet.
    out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
                          "*.rs"], cwd=REPO, capture_output=True, text=True, check=True).stdout
    return sorted(f for f in out.split("\0") if f and not f.startswith("docs/archive/"))


def count_tests(text: str) -> int:
    return sum(1 for line in text.splitlines() if TEST_ATTR.match(line))


def static_gaps(files: dict[str, str], carriers: set[str]) -> list[str]:
    """Files holding tests that no crate root a `rust_test` compiles reaches."""
    return [
        f"{path}: {count} test(s) that no Bazel test target compiles — no crate root a "
        f"`rust_test` builds declares this module"
        for path, text in sorted(files.items())
        if (count := count_tests(text)) and path not in carriers
    ]
