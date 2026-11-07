# SPDX-License-Identifier: Apache-2.0
"""Resolving a path token against the repository: repo-relative, file-relative, then any suffix."""

from __future__ import annotations

import posixpath
from pathlib import Path


def candidates(token: str, source: str) -> list[str]:
    """Repo-relative, then relative to the referencing file's directory.

    Normalised textually rather than through the filesystem: `..` must be resolved
    against the repository root, and `Path.resolve()` answers about the machine the
    gate happens to run on.
    """
    parent = posixpath.dirname(source)
    forms = [posixpath.normpath(token)]
    if parent:
        forms.append(posixpath.normpath(posixpath.join(parent, token)))
    return [f for f in forms if not f.startswith("..")]


def resolves(token: str, source: str, repo_files: set[str]) -> bool:
    forms = candidates(token, source)
    if any(f in repo_files for f in forms):
        return True
    suffix = "/" + posixpath.normpath(token)
    return any(f.endswith(suffix) for f in repo_files)


def on_disk(token: str, root: Path, source: str) -> bool:
    return any((root / f).exists() for f in candidates(token, source))
