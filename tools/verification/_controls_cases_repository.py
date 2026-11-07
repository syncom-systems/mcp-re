# SPDX-License-Identifier: Apache-2.0
"""Repository scope — the census may only see files a commit could contain."""

from __future__ import annotations

import subprocess
from pathlib import Path

import _control_files
import _controls


def _is_ignored(path: Path) -> bool:
    return subprocess.run(
        ["git", "-C", str(_controls.REPO_ROOT), "check-ignore", "-q", str(path)],
        capture_output=True,
    ).returncode == 0


def _forget_the_repository_listing() -> None:
    """Drop the memoised listing, tolerating its absence.

    Tolerating it is the point: an implementation with no repository listing at all is
    exactly the defect, and this control must then fail on the MEMBERSHIP assertion below
    rather than on an `AttributeError` here. A probe that goes red because a symbol is
    missing proves the symbol is missing, not that the census is scoped.
    """
    cache = getattr(_control_files, "_repository_files", None)
    clear = getattr(cache, "cache_clear", None)
    if clear is not None:
        clear()


def test_a_gitignored_file_is_outside_the_census_and_a_tracked_sibling_is_not():
    """A control that is not IN the repository is not a control OF it.

    The defect this refuses was measured at `9e0ba722`: `walk` pruned a fixed list of
    directory names and knew nothing about `.gitignore`, so an investigation's files under
    the ignored `/work/` tree entered the census and `scripts/control_census_gate.py` went
    RED on 54 files that are in no commit and that CI therefore never sees. One merge-path
    gate, two different verdicts on one revision, decided by what happened to be lying in a
    developer's ignored directories.

    Both directions are asserted, because only the pair is a control. Ignoring everything
    would also make the false red go away, and would make the census measure nothing: the
    fix must drop the ignored file and KEEP its non-ignored sibling. The sibling is
    untracked-but-not-ignored on purpose — that is the case `--cached` alone would lose,
    and a newly written control is exactly when a census is most useful.
    """
    root = _controls.REPO_ROOT
    ignored = root / "work" / "_census_scope_probe_ignored.py"
    visible = root / "tools" / "verification" / "_census_scope_probe_visible.py"
    body = "# SPDX-License-Identifier: Apache-2.0\n# census repository-scope probe\n"
    try:
        ignored.parent.mkdir(parents=True, exist_ok=True)
        ignored.write_text(body)
        visible.write_text(body)
        assert _is_ignored(ignored), f"{ignored} must be gitignored for this control to mean anything"
        assert not _is_ignored(visible), f"{visible} must NOT be gitignored"
        _forget_the_repository_listing()
        seen = set(_controls.walk(".py"))
        assert visible in seen, "an untracked, non-ignored file left the census"
        assert ignored not in seen, "a gitignored file entered the census"
    finally:
        ignored.unlink(missing_ok=True)
        visible.unlink(missing_ok=True)
        _forget_the_repository_listing()
