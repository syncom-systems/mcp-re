# SPDX-License-Identifier: Apache-2.0
"""pytest controls: every collected test function, named relative to its project."""

from __future__ import annotations

import re
from pathlib import Path

from _control_files import skipped, walk
from _control_model import Control
from _ecosystems import REPO_ROOT

_PY_TEST = re.compile(r"^(\s*)(?:async\s+)?def\s+(test_[A-Za-z0-9_]+)")
_PY_CLASS = re.compile(r"^class\s+(Test[A-Za-z0-9_]*)")


def _nearest_project(path: Path, manifest: str) -> Path:
    """The nearest ancestor holding `manifest`, or the repository root if none does."""
    current = path.parent
    while current != REPO_ROOT:
        if (current / manifest).is_file():
            return current
        current = current.parent
    return REPO_ROOT


def _is_pytest_file(path: Path) -> bool:
    return path.name.startswith("test_") or path.name.endswith("_test.py")


def _pytest_cases_in(path: Path, project: str, selector_base: str, rel_repo: Path) -> list[Control]:
    out: list[Control] = []
    current_class: str | None = None
    for number, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
        klass = _PY_CLASS.match(line)
        if klass:
            current_class = klass.group(1)
            continue
        match = _PY_TEST.match(line)
        if not match:
            continue
        nested = bool(match.group(1)) and current_class is not None
        owner = f"{current_class}::" if nested else ""
        out.append(
            Control(
                project=project,
                identity=f"pytest#{selector_base}::{owner}{match.group(2)}",
                kind="pytest",
                carrier=rel_repo.as_posix(),
                line=number,
            )
        )
    return out


def _pytest_file_controls(path: Path) -> list[Control]:
    rel_repo = path.relative_to(REPO_ROOT)
    if skipped(rel_repo) or not _is_pytest_file(path):
        return []
    project = _nearest_project(path, "pyproject.toml")
    return _pytest_cases_in(
        path,
        project.relative_to(REPO_ROOT).as_posix() or ".",
        path.relative_to(project).as_posix(),
        rel_repo,
    )


def pytest_controls() -> list[Control]:
    """Every pytest function, named as `pytest#<path relative to its project>::<fn>`.

    Project-relative because that is what the selector is: the lane runs pytest with the
    project as its working directory, so a repo-relative path would select nothing. A file
    under no `pyproject.toml` — `tools/verification/test_*.py`, the verification suite's own
    controls — is relative to the repository root, which is where those are run from.
    """
    return [control for path in walk(".py") for control in _pytest_file_controls(path)]
