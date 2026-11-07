# SPDX-License-Identifier: Apache-2.0
"""Which files of this repository the census may read.

A control that is not in the repository is not a control OF the repository, so the
enumerators share one walk that knows what a commit could contain.
"""

from __future__ import annotations

import subprocess
from functools import lru_cache
from pathlib import Path

from _ecosystems import REPO_ROOT

#: Directories that are not source of this repository. Every dotted directory is skipped
#: as well — `sdk/python/.venv*/lib/.../site-packages` holds thousands of a dependency's own
#: tests, and counting them would put a census's largest population outside the repository
#: it claims to measure.
_SKIP = {"target", "node_modules", "dist", "build", "__pycache__", "site-packages"}


@lru_cache(maxsize=1)
def _repository_files() -> frozenset[Path] | None:
    """Every path a COMMIT of this repository could contain — tracked, plus untracked and
    not ignored. `None` when git cannot answer, and the walk then falls back to pruning.

    A control that is not in the repository is not a control OF the repository, and the
    directory-name prune cannot express that: it prunes a fixed list of names and has no
    idea what `.gitignore` says. Measured consequence at `9e0ba722` — this repository's own
    `/work/` tree is gitignored, an investigation left Python files there, and
    `scripts/control_census_gate.py` went **red locally on files that are in no commit and
    that CI therefore never sees**. A merge-path gate whose verdict depends on what happens
    to be lying in a developer's ignored directories is a gate with two different answers.

    `--cached --others --exclude-standard` is the exact set, not an approximation of it: it
    is what `git status` would offer to commit. Scanning only tracked files would be the
    other error — a newly written control would go uncensused until someone committed it,
    which is precisely when a census is most useful.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            capture_output=True, check=True, text=True, timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    names = [n for n in out.split("\0") if n]
    if not names:
        return None
    return frozenset((REPO_ROOT / n).resolve() for n in names)


def _in_repository(path: Path) -> bool:
    known = _repository_files()
    if known is None:
        return True
    try:
        return path.resolve() in known
    except OSError:
        return False


def skipped(path: Path) -> bool:
    """Name-based pruning only.

    `_in_repository` deliberately does NOT belong here: `doctest_controls` calls this with a
    path RELATIVE to a crate's `src/`, which resolves against the process's working directory
    and is in no repository listing. Adding the membership test here silently emptied the
    `rust-doctest` kind — three of `test_controls.py`'s cases caught it, which is why touching
    anything under `tools/verification/` means running all of them.
    """
    return any(_prune(part) for part in path.parts)


def _prune(name: str) -> bool:
    return name in _SKIP or name.startswith(".")


def _children(directory: Path) -> list[Path]:
    try:
        return sorted(directory.iterdir())
    except OSError:
        return []


def _is_wanted_file(entry: Path, suffix: str) -> bool:
    return (entry.suffix == suffix or entry.name == suffix) and _in_repository(entry)


def _is_followed_directory(entry: Path) -> bool:
    return entry.is_dir() and not _prune(entry.name)


def _scan(directory: Path, suffix: str) -> tuple[list[Path], list[Path]]:
    """The directories to descend into and the wanted files directly inside `directory`."""
    subdirectories: list[Path] = []
    files: list[Path] = []
    for entry in _children(directory):
        if entry.is_symlink():
            # `bazel-bin` and its siblings are symlinks into the output base, which
            # holds every vendored crate's source. `rglob` never followed them;
            # `iterdir` + `is_dir` does, and following one puts 800 third-party
            # packages into a census of this repository's controls.
            continue
        if _is_followed_directory(entry):
            subdirectories.append(entry)
        elif not entry.is_dir() and _is_wanted_file(entry, suffix):
            files.append(entry)
    return subdirectories, files


def walk(suffix: str, root: Path | None = None) -> list[Path]:
    """Every file whose suffix or whole NAME is `suffix`, pruning skipped directories.

    The name form is what finds manifests — `package.json`'s suffix is `.json`, which many
    fixtures share — and the suffix form is what finds source.

    `rglob` then filter is the obvious spelling and it is the wrong one here: it descends
    into `target/`, which holds hundreds of thousands of build artefacts, so the census
    spends minutes reading a tree it discards. Pruning at the directory makes the walk
    proportional to the repository rather than to the last build.
    """
    found: list[Path] = []
    stack = [REPO_ROOT if root is None else root]
    while stack:
        subdirectories, files = _scan(stack.pop(), suffix)
        stack.extend(subdirectories)
        found.extend(files)
    return sorted(found)
