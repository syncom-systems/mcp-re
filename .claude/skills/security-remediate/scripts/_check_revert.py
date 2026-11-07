"""Touching the tree: rustfmt over the touched files, and the revert of a red change."""
from __future__ import annotations

import os
import shutil
import subprocess

import writer_patch
from _check_support import slug


def _reformatted(rustfmt: str, path: str) -> str | None:
    """The file's source after rustfmt, or None when rustfmt fails or changes nothing."""
    src = open(path, encoding="utf-8").read()
    proc = subprocess.run([rustfmt, "--edition", "2021", "--emit", "stdout"], input=src,
                          capture_output=True, text=True)
    formatted = proc.stdout if proc.returncode == 0 else ""
    return formatted if formatted and formatted != src else None


def format_touched(touched: list[str], rustfmt: str | None = None) -> list[str]:
    """Format each touched .rs file in place and return the ones that changed.

    Each file goes through stdin, so rustfmt formats exactly that file and never follows its
    `mod` declarations into files the writer did not touch. A file rustfmt cannot parse is
    left as it is: the rustfmt gate part reports it, blamed on this writer."""
    rustfmt = rustfmt or shutil.which("rustfmt")
    if not rustfmt:
        return []
    changed = []
    for path in [p for p in touched if p.endswith(".rs") and os.path.isfile(p)]:
        formatted = _reformatted(rustfmt, path)
        if formatted is not None:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(formatted)
            changed.append(path)
    return changed


def _write_patch(patch: str, touched: list[str], tracked: list[str]) -> None:
    with open(patch, "w", encoding="utf-8") as fh:
        fh.write(subprocess.run(["git", "diff", "HEAD", "--", *tracked], capture_output=True,
                                text=True).stdout)
        for f in [f for f in touched if f not in tracked and os.path.isfile(f)]:
            fh.write("\n# untracked %s\n" % f + open(f, encoding="utf-8", errors="replace").read())


def revert(touched: list[str], work_dir: str, store: str | None = None,
           file: str | None = None) -> str:
    """Save the change as a patch, then return the touched paths to where this writer
    found them.

    A red change left in the tree makes the next writer's gate fail on it, and the
    lane's attribution — one writer, so a failure is that writer's — collapses. The
    patch keeps the work; the tree goes back to the state the next writer expects.

    With a `pre` snapshot that state is the snapshot, not HEAD: earlier writers' accepted
    but uncommitted hunks in a shared file survive. Without one (a direct call), HEAD.
    """
    patch = os.path.join(work_dir, "gate-failed-%s.patch" % slug(",".join(touched)))
    own = writer_patch.patch_path(store, file) if store and file else None
    if own and writer_patch.restore(store, file, touched):
        shutil.copyfile(own, patch)
        return patch
    tracked = subprocess.run(["git", "ls-files", "--", *touched], capture_output=True,
                             text=True).stdout.split()
    _write_patch(patch, touched, tracked)
    if tracked:
        subprocess.run(["git", "checkout", "HEAD", "--", *tracked], check=False)
    for f in [f for f in touched if f not in tracked and os.path.isfile(f)]:
        os.remove(f)
    return patch
