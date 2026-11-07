# SPDX-License-Identifier: Apache-2.0
"""Scanning the repository's files for path tokens that resolve to nothing."""

from __future__ import annotations

import fnmatch
import subprocess
from collections.abc import Iterator
from pathlib import Path

from _doc_path.config import CODE_SUFFIXES, COMMENT, MAX_BYTES, SCOPE_EXCLUDE, STRIKE, TOKEN
from _doc_path.lines import exempt_lines, fence_langs, mechanically_excluded
from _doc_path.resolve import on_disk, resolves


def repository_files(root: Path) -> set[str]:
    """Tracked plus untracked-not-ignored: what `git status` would offer to commit."""
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {p for p in out.split("\0") if p}


def in_scope(path: str) -> bool:
    return not any(fnmatch.fnmatch(path, pat) for pat in SCOPE_EXCLUDE)


def _tokens_to_resolve(line: str, lang: str | None) -> Iterator[str]:
    """The path tokens of `line` that no strike-through or mechanical rule removes."""
    struck = {m.group(1) for m in STRIKE.finditer(line)}
    for match in TOKEN.finditer(line):
        token = match.group(1)
        if any(token in s for s in struck):
            continue
        if mechanically_excluded(line, match.start(1), token, lang):
            continue
        yield token


def _failure_class(token: str, source: str, root: Path, repo_files: set[str]) -> str | None:
    """None when the token resolves; otherwise DEAD, or GITIGNORED if only a path outside
    the repository answers to it."""
    if resolves(token, source, repo_files):
        return None
    return "GITIGNORED" if on_disk(token, root, source) else "DEAD"


def _scannable_lines(lines: list[str], exempt: set[int], comments_only: bool) -> Iterator[tuple[int, str]]:
    """The lines a document is read through: all of them, or only a code file's comments,
    minus those a carve-out exempts."""
    for idx, line in enumerate(lines):
        if idx in exempt or (comments_only and not COMMENT.match(line)):
            continue
        yield idx, line


def scan_file(
    source: str, text: str, root: Path, repo_files: set[str]
) -> list[tuple[int, str, str]]:
    """Return `(lineno, token, class)` for every token that does not resolve."""
    lines = text.splitlines()
    langs = fence_langs(lines)
    scannable = _scannable_lines(lines, exempt_lines(lines), source.endswith(CODE_SUFFIXES))
    classified = (
        (idx, token, _failure_class(token, source, root, repo_files))
        for idx, line in scannable
        for token in _tokens_to_resolve(line, langs[idx])
    )
    return [(idx + 1, token, kind) for idx, token, kind in classified if kind is not None]


def _is_readable_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BYTES


def _readable_text(path: Path) -> str | None:
    if not _is_readable_file(path):
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def measure(root: Path, repo_files: set[str] | None = None) -> dict[str, list[str]]:
    """Every in-scope file's unresolved tokens, as `line: token — class` strings."""
    files = repository_files(root) if repo_files is None else repo_files
    result: dict[str, list[str]] = {}
    for rel in sorted(files):
        if not in_scope(rel):
            continue
        text = _readable_text(root / rel)
        if text is None:
            continue
        hits = scan_file(rel, text, root, files)
        if hits:
            result[rel] = [f"{n}: {tok} — {kind}" for n, tok, kind in hits]
    return result


def scanned_count(root: Path, repo_files: set[str] | None = None) -> int:
    files = repository_files(root) if repo_files is None else repo_files
    return sum(1 for rel in files if in_scope(rel) and (root / rel).is_file())
