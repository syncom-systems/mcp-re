# SPDX-License-Identifier: Apache-2.0
"""Library targets: every file the module tree reaches is in the target's `srcs`."""

from __future__ import annotations

from pathlib import Path

import _module_tree
import _rust_targets


def _unlisted_findings(root: Path, label: str, tree, listed: set[str]) -> list[str]:
    findings: list[str] = []
    for module in tree.files:
        rel = module.path.relative_to(root).as_posix()
        if rel in listed:
            continue
        declared = module.declared_by.relative_to(root).as_posix() if module.declared_by else "?"
        findings.append(
            f"{label}: `mod {module.module[-1]};` in {declared} needs {rel} in the target's "
            f"srcs — rustc compiles it, Bazel cannot find it (E0583). If BUILD.bazel already "
            f"lists it, regenerate the table: `tools/verification/rust-targets --write`"
        )
    return findings


def _unresolved_findings(root: Path, label: str, tree) -> list[str]:
    return [
        f"{label}: `mod {decl.name};` in {declaring.relative_to(root).as_posix()} "
        f"names no file — rustc cannot compile it either"
        for declaring, decl in tree.unresolved
    ]


def _missing_file_findings(root: Path, label: str, listed: set[str]) -> list[str]:
    return [
        f"{label}: lists {entry}, which does not exist"
        for entry in sorted(listed)
        if not (root / entry).is_file()
    ]


def check_library(root: Path, label: str, row: dict) -> list[str]:
    """Findings for one library target: every file its module tree reaches is in its
    `srcs`, every listed file exists, and every declaration resolves.

    The tree is walked to the bottom even under an unlisted file: one run names every
    missing entry, not one per re-run.
    """
    listed = set(row["srcs"])
    tree = _module_tree.walk(root / row["root"])
    return (
        _unlisted_findings(root, label, tree, listed)
        + _unresolved_findings(root, label, tree)
        + _missing_file_findings(root, label, listed)
    )


def check_libraries(root: Path) -> tuple[list[str], int]:
    """Every library target in the table against its module tree. Returns the findings and
    how many libraries were checked."""
    rows = _rust_targets.rows_at(root)
    findings: list[str] = []
    libraries = sorted(label for label, row in rows.items() if row["kind"] == "rust_library")
    for label in libraries:
        findings.extend(check_library(root, label, rows[label]))
    return findings, len(libraries)
