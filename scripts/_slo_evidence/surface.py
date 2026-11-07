# SPDX-License-Identifier: Apache-2.0
"""The performance surface: every declared input, git-tracked, folded into one digest."""

from __future__ import annotations

import hashlib
import subprocess
import tomllib
from pathlib import Path

from _slo_evidence import config
from _slo_evidence.config import REPO, SECTIONS


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _tracked(paths: list[Path]) -> set[Path]:
    """The subset git tracks. One call, not one per file: this runs on ~400 paths."""
    listing = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "-z", "--", *[str(p.relative_to(REPO)) for p in paths]],
        capture_output=True,
        text=True,
        check=False,
    )
    return {REPO / name for name in listing.stdout.split("\0") if name}


def _expand(entry: str) -> set[Path]:
    """The files one declared entry names: a file itself, or every file under a directory."""
    target = REPO / entry
    if target.is_dir():
        return {p for p in target.rglob("*") if p.is_file()}
    if target.is_file():
        return {target}
    raise SystemExit(f"error: config/performance-surface.toml declares {entry!r}, which does not exist")


def declared_inputs() -> list[Path]:
    """Every file the declaration names, expanded, sorted, deduplicated."""
    declared = tomllib.loads(config.SURFACE_TOML.read_text(encoding="utf-8"))["surface"]
    found: set[Path] = set()
    for section in SECTIONS:
        for entry in declared[section]:
            found |= _expand(entry)
    return sorted(found)


def fold(digests: dict[str, str]) -> str:
    """The surface fingerprint over `{relative path: digest}`."""
    return sha256("\n".join(f"{path} {digest}" for path, digest in sorted(digests.items())).encode())


def performance_surface() -> tuple[str, dict[str, str]]:
    """`(fingerprint, {relative path: digest})` over every declared input."""
    inputs = declared_inputs()
    tracked = _tracked(inputs)
    untracked = sorted(str(p.relative_to(REPO)) for p in inputs if p not in tracked)
    if untracked:
        raise SystemExit(
            "error: these declared performance-surface inputs are NOT tracked by git:\n  "
            + "\n  ".join(untracked)
            + "\n       A fingerprint input outside the tree makes one commit fingerprint two ways."
        )
    digests = {str(p.relative_to(REPO)): sha256(p.read_bytes()) for p in inputs}
    return fold(digests), digests
