# SPDX-License-Identifier: Apache-2.0
"""The audit-vocabulary guard's hand lists against the module trees the build graph compiles."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import _module_tree
import _rust_targets
from workflow_reader import glob_matches

from _bazel_srcs.config import GUARD
from _bazel_srcs.starlark import first_strings, guard_patterns, quoted_strings, rust_slice_const

#: A package's `(include, exclude)` glob patterns, or `None` when its `srcs` is unread.
Patterns = tuple[list[str], list[str]] | None


@dataclass(frozen=True)
class GuardLists:
    """The four hand lists the guard test declares."""

    scanned: set[str]
    not_scanned: set[str]
    kinds: set[str]
    dirs: list[str]


def read_guard_lists(root: Path) -> GuardLists:
    guard = (root / GUARD).read_text(encoding="utf-8")
    return GuardLists(
        scanned=set(first_strings(rust_slice_const(guard, "CRATE_SOURCE_TREES"))),
        not_scanned=set(first_strings(rust_slice_const(guard, "NOT_SCANNED"))),
        kinds=set(quoted_strings(rust_slice_const(guard, "CRATE_KINDS"))),
        dirs=quoted_strings(rust_slice_const(guard, "COMPILED_SOURCE_DIRS")),
    )


def package_findings(rows: dict, lists: GuardLists) -> list[str]:
    """Crate packages the two hand lists disagree with the build graph about."""
    crate_packages = {row["package"] for row in rows.values() if row["kind"] in lists.kinds}
    findings = [
        f"{GUARD}: crate package {package} is in neither CRATE_SOURCE_TREES nor NOT_SCANNED "
        f"— the guard scans it by nobody"
        for package in sorted(crate_packages - lists.scanned - lists.not_scanned)
    ]
    findings += [
        f"{GUARD}: CRATE_SOURCE_TREES names {package}, which compiles no crate"
        for package in sorted(lists.scanned - crate_packages)
    ]
    return findings


class GlobCache:
    """Each package's `guard_src_files` patterns, read once. An unreadable one is a finding,
    appended to the caller's list at the point it is first met."""

    def __init__(self, root: Path, findings: list[str]) -> None:
        self._root = root
        self._patterns: dict[str, Patterns] = {}
        self._findings = findings

    def patterns(self, package: str) -> Patterns:
        if package not in self._patterns:
            self._patterns[package] = self._read(package)
        return self._patterns[package]

    def _read(self, package: str) -> Patterns:
        build = self._root / package / "BUILD.bazel"
        try:
            return guard_patterns(build.read_text(encoding="utf-8")) if build.is_file() else ([], [])
        except ValueError as exc:
            self._findings.append(f"{package}/BUILD.bazel: {exc}")
            return None


def _outside_walked_dirs(label: str, rel: str, package: str, dirs: list[str]) -> str:
    return (
        f"{label} compiles {rel}, outside the {dirs} the audit-vocabulary guard "
        f"walks in {package} — the guard never reads it"
    )


def _not_globbed(label: str, rel: str, package: str) -> str:
    return (
        f"{label} compiles {rel}, which {package}:guard_src_files does not glob — "
        f"the guard's runfiles do not carry it"
    )


def _carried(within: str, read: tuple[list[str], list[str]]) -> bool:
    included = any(glob_matches(p, within) for p in read[0])
    excluded = any(glob_matches(p, within) for p in read[1])
    return included and not excluded


@dataclass(frozen=True)
class Target:
    """A crate target the guard scans, with its package's glob patterns."""

    label: str
    package: str
    read: Patterns


def module_finding(target: Target, rel: str, lists: GuardLists) -> str | None:
    """The finding for one compiled file, or `None` when the guard reads it and carries it."""
    package = target.package
    within = rel[len(package) + 1 :] if rel.startswith(f"{package}/") else None
    if within is None or not any(within.startswith(f"{d}/") for d in lists.dirs):
        return _outside_walked_dirs(target.label, rel, package, lists.dirs)
    if target.read is not None and not _carried(within, target.read):
        return _not_globbed(target.label, rel, package)
    return None


def _is_guarded(row: dict, lists: GuardLists) -> bool:
    return row["kind"] in lists.kinds and row["package"] in lists.scanned and not row["testonly"]


def _guarded_rows(rows: dict, lists: GuardLists):
    """The targets the guard scans, in label order. A test-only target is linked by tests
    alone — Bazel refuses any other consumer — so its sources are test sources, which the
    guard does not scan by design."""
    for label, row in sorted(rows.items()):
        if _is_guarded(row, lists):
            yield label, row, row["package"]


def check_source_trees(root: Path) -> tuple[list[str], int]:
    """The audit-vocabulary guard's hand lists against the module trees of the crate
    targets the build graph compiles. Returns the findings and how many files were checked.
    """
    lists = read_guard_lists(root)
    rows = _rust_targets.rows_at(root)
    findings = package_findings(rows, lists)
    checked = 0
    base = root.resolve()
    cache = GlobCache(root, findings)
    for label, row, package in _guarded_rows(rows, lists):
        target = Target(label, package, cache.patterns(package))
        for module in _module_tree.walk(root / row["root"]).files:
            checked += 1
            finding = module_finding(target, os.path.relpath(module.path.resolve(), base), lists)
            if finding is not None:
                findings.append(finding)
    return findings, checked
