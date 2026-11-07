# SPDX-License-Identifier: Apache-2.0
"""Running gazelle in read-only diff mode and splitting its unified diff per file."""

from __future__ import annotations

import subprocess
import sys


def run_gazelle_diff() -> str:
    """Run the generator in read-only diff mode; return its unified diff."""
    proc = subprocess.run(
        ["bazel", "run", "//:gazelle", "--", "-mode", "diff"],
        capture_output=True,
        text=True,
    )
    # gazelle exits nonzero simply because a diff exists; that is not an error
    # here. A genuine failure (missing target, bad directive) prints to stderr.
    if proc.returncode not in (0, 1, 2, 3):
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"gazelle diff failed (exit {proc.returncode})")
    return proc.stdout


def _diff_path(header: str) -> str:
    return header[4:].split("\t", 1)[0].strip()


def parse_per_file(diff: str) -> dict[str, list[tuple[str, str]]]:
    """Split the unified diff into {file: [(sign, trimmed_content), ...]}.

    sign is '+', '-', or ' ' (context). Order is preserved so we can tell a
    label INSERTED into an existing list (context opener) from a whole-attribute
    replacement (added opener).
    """
    files: dict[str, list[tuple[str, str]]] = {}
    cur: list[tuple[str, str]] | None = None
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            cur = files.setdefault(_diff_path(raw), [])
        elif raw.startswith(("--- ", "@@")) or cur is None:
            continue
        elif raw and raw[0] in "+- ":
            cur.append((raw[0], raw[1:].strip()))
    return files
