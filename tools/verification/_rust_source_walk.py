# SPDX-License-Identifier: Apache-2.0
"""The walk that finds production Rust files."""

from __future__ import annotations

from pathlib import Path

#: Directories that are not this repository's production Rust.
SKIP_DIRS = {"target", "node_modules", ".git", "bazel-out", "vendor"}

#: Directories under a crate whose Rust is compiled into no shipped library or binary.
NON_PRODUCTION_DIRS = {"tests", "benches", "examples"}


def _dirs_between(root: Path, path: Path) -> list[Path]:
    """`root` and every directory below it that contains `path`."""
    out = [root]
    for part in path.relative_to(root).parts[:-1]:
        out.append(out[-1] / part)
    return out


def _crate_target_dir(directory: Path) -> bool:
    """`directory` is a crate's `tests/`, `benches/` or `examples/`: it sits beside the
    crate's `Cargo.toml`. A tests-only crate has no `src/`, so `src/` is not the marker."""
    return directory.name in NON_PRODUCTION_DIRS and (directory.parent / "Cargo.toml").is_file()


def _production(root: Path, p: Path) -> bool:
    rel = p.relative_to(root)
    if any(part in SKIP_DIRS for part in rel.parts):
        return False
    if any(_crate_target_dir(d) for d in _dirs_between(root, p)):
        return False
    return p.name != "build.rs"


def crate_sources(root: Path) -> list[Path]:
    """Every production `.rs` under `root`, sorted.

    Skips build outputs and vendored trees, a crate's `tests/`, `benches/` and `examples/`
    directories, and `build.rs`: none of those is compiled into a shipped library or binary.
    A directory of those names inside `src/` is a production module and is walked.
    """
    return [p for p in sorted(root.rglob("*.rs")) if _production(root, p)]
