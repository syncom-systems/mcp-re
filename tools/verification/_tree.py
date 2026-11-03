# SPDX-License-Identifier: Apache-2.0
"""The source tree a measurement reads — the seam between the verification tools and bytes.

A fingerprint is a statement about a TREE: the files a unit's evidence depends on, read at
one point in history. Until this seam existed every reader resolved paths against the
working directory, so a tree other than the checkout could be measured only by checking it
out. `select-units` did exactly that for a merge base, in a temporary git worktree, and the
fingerprint's read set could be observed only by patching `builtins.open` process-wide.

Two adapters satisfy the seam:

  * `WorkingTree` — the checkout under a root, as every reader read it before;
  * `CommitTree`  — the tree of one commit, read from the object database. Its files are
    exactly the commit's, so it has no untracked files and no ignored build output.

`current()` is the tree the readers consult, the working tree unless a caller is inside
`reading(tree)`. Readers that resolve a repo-relative path — the fingerprint, the registry
and target-table loaders, the manifest's path checks, the Lean closure, project discovery —
go through it, so a whole measurement moves to another tree by entering one block.
"""

from __future__ import annotations

import subprocess
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path, PurePosixPath
from typing import Callable, Generator, Protocol, TypeVar

REPO_ROOT = Path(__file__).resolve().parents[2]

T = TypeVar("T")


class TreeError(RuntimeError):
    """The tree cannot answer: git failed, or a commit does not resolve."""


class SourceTree(Protocol):
    """What a measurement may ask of the bytes it is about. Paths are repo-relative POSIX."""

    def files(self, pattern: str) -> list[str]:
        """The files `pattern` matches, sorted. Glob syntax is `PurePath.full_match`'s."""
        ...

    def read(self, rel: str) -> bytes:
        """The bytes of `rel`. Raises `FileNotFoundError` when the tree has no such file."""
        ...

    def is_file(self, rel: str) -> bool:
        """Whether the tree holds a file at `rel`."""
        ...

    def tracked(self) -> frozenset[str]:
        """Every file git tracks in this tree."""
        ...

    def memo(self, key: str, compute: Callable[[], T]) -> T:
        """`compute()`, once per tree: a value derived from this tree's bytes alone."""
        ...


class _Memo:
    def __init__(self) -> None:
        self._values: dict[str, object] = {}

    def memo(self, key: str, compute: Callable[[], T]) -> T:
        if key not in self._values:
            self._values[key] = compute()
        return self._values[key]  # type: ignore[return-value]

    def forget(self) -> None:
        """Drop every memoized value, for a caller that changed the bytes under the tree."""
        self._values.clear()


class WorkingTree(_Memo):
    """The checkout under `root`, untracked files included, as the filesystem shows it."""

    def __init__(self, root: Path = REPO_ROOT) -> None:
        super().__init__()
        self.root = root

    def files(self, pattern: str) -> list[str]:
        return sorted(
            path.relative_to(self.root).as_posix()
            for path in self.root.glob(pattern)
            if path.is_file()
        )

    def read(self, rel: str) -> bytes:
        return (self.root / rel).read_bytes()

    def is_file(self, rel: str) -> bool:
        return (self.root / rel).is_file()

    def tracked(self) -> frozenset[str]:
        return self.memo("tracked", lambda: _ls_files(self.root))


class CommitTree(_Memo):
    """The tree of `commit` in the repository at `root`, read from the object database.

    One `git ls-tree` lists it and one long-lived `git cat-file --batch` serves every read,
    so measuring a whole registry at a commit costs two processes rather than one per file.
    """

    def __init__(self, commit: str, root: Path = REPO_ROOT) -> None:
        super().__init__()
        self.root = root
        self.commit = _resolve(commit, root)
        self._blobs = _ls_tree(self.commit, root)
        self._cat: subprocess.Popen[bytes] | None = None
        self._lock = threading.Lock()

    def files(self, pattern: str) -> list[str]:
        # A commit's tree cannot change, so each pattern is matched once. Only the blobs
        # under the pattern's literal directory prefix can match it.
        def match() -> list[str]:
            literal = pattern.split("/")
            prefix = []
            for segment in literal[:-1]:
                if any(ch in segment for ch in "*?["):
                    break
                prefix.append(segment)
            under = "/".join(prefix) + "/" if prefix else ""
            return sorted(
                rel
                for rel in self._blobs
                if rel.startswith(under) and PurePosixPath(rel).full_match(pattern)
            )

        return self.memo(f"files:{pattern}", match)

    def read(self, rel: str) -> bytes:
        oid = self._blobs.get(rel)
        if oid is None:
            raise FileNotFoundError(f"{rel} is not in the tree of {self.commit[:12]}")
        return self.memo(f"blob:{oid}", lambda: self._cat_blob(oid))

    def is_file(self, rel: str) -> bool:
        return rel in self._blobs

    def tracked(self) -> frozenset[str]:
        return frozenset(self._blobs)

    def _cat_blob(self, oid: str) -> bytes:
        with self._lock:
            if self._cat is None:
                self._cat = subprocess.Popen(
                    ["git", "cat-file", "--batch"],
                    cwd=self.root,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                )
            assert self._cat.stdin is not None and self._cat.stdout is not None
            self._cat.stdin.write(oid.encode() + b"\n")
            self._cat.stdin.flush()
            header = self._cat.stdout.readline().split()
            if len(header) != 3 or header[1] != b"blob":
                raise TreeError(f"git cat-file could not read blob {oid}: {header!r}")
            body = self._cat.stdout.read(int(header[2]))
            self._cat.stdout.read(1)
            return body

    def close(self) -> None:
        with self._lock:
            if self._cat is not None:
                assert self._cat.stdin is not None
                self._cat.stdin.close()
                self._cat.wait()
                self._cat = None


def _resolve(commit: str, root: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise TreeError(f"{commit!r} does not resolve to a commit in {root}")
    return proc.stdout.strip()


def _ls_tree(commit: str, root: Path) -> dict[str, str]:
    """Every blob of `commit`'s tree, by repo-relative path. Submodules are not files here."""
    proc = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", commit],
        cwd=root,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise TreeError(f"git ls-tree {commit}: {proc.stderr.decode('utf-8', 'replace').strip()}")
    blobs: dict[str, str] = {}
    for entry in proc.stdout.split(b"\0"):
        if not entry:
            continue
        meta, _, rel = entry.partition(b"\t")
        _, kind, oid = meta.split()
        if kind == b"blob":
            blobs[rel.decode("utf-8")] = oid.decode()
    return blobs


def _ls_files(root: Path) -> frozenset[str]:
    """Every path git tracks under `root`.

    No git, no answer: returning "everything is tracked" would let an untracked file reach
    a digest and make one commit fingerprint two ways depending on whose machine looked.
    """
    proc = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        raise TreeError("git ls-files failed; the tree cannot say what it tracks")
    return frozenset(entry for entry in proc.stdout.split("\0") if entry)


_WORKING = WorkingTree()
_CURRENT: ContextVar[SourceTree | None] = ContextVar("source_tree", default=None)


def current() -> SourceTree:
    """The tree the readers consult: the working tree unless inside `reading`."""
    return _CURRENT.get() or _WORKING


@contextmanager
def reading(tree: SourceTree) -> Generator[SourceTree]:
    """Every tree-aware reader, for the length of the block, reads `tree`."""
    token = _CURRENT.set(tree)
    try:
        yield tree
    finally:
        _CURRENT.reset(token)


def text(rel: str) -> str:
    """`rel` from the current tree, as UTF-8 text."""
    return current().read(rel).decode("utf-8")


def _in_repo(path: Path) -> str | None:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return None


def read_path(path: Path) -> bytes:
    """The bytes at absolute `path`: from the current tree when it lies in the repository,
    from the filesystem when it is a scratch tree a selftest built outside it."""
    rel = _in_repo(path)
    return path.read_bytes() if rel is None else current().read(rel)


def path_is_file(path: Path) -> bool:
    """`read_path`'s counterpart for existence."""
    rel = _in_repo(path)
    return path.is_file() if rel is None else current().is_file(rel)


def expand(patterns) -> set[str]:
    """The files of the current tree a `paths` list names, with its globs expanded."""
    tree = current()
    return {rel for pattern in patterns for rel in tree.files(pattern)}
