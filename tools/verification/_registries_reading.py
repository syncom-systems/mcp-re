# SPDX-License-Identifier: Apache-2.0
"""Reading the policy registries: the registry table, the TOML parse (cached per text), and
the readers that answer from the working tree, a scratch tree or a commit.

`parse`, `read`, `document`, `rows`, `text`, `text_at` and `blob_at` are the only code that
turns a policy registry's bytes into data. Stdlib only, and it imports nothing from this
package outside the `_registries` family: every typed loader imports it.
"""

from __future__ import annotations

import copy
import functools
import subprocess
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_RELATIVE = "verification/policy"
POLICY_DIR = REPO_ROOT / POLICY_RELATIVE

#: Every registry this module reads, by the name its callers use.
REGISTRIES = {
    "verification": "verification.toml",
    "theorems": "theorems.toml",
    "assumptions": "assumptions.toml",
    "trust-boundaries": "trust-boundaries.toml",
    "mutation-probes": "mutation-probes.toml",
    "structural-probes": "structural-probes.toml",
    "measurements": "measurements.toml",
    "control-dispositions": "control-dispositions.toml",
    "toolchains": "toolchains.lock.toml",
}

#: The registries `reader_problems` holds to this module: every one it reads.
GUARDED = frozenset(REGISTRIES)


class ManifestError(Exception):
    """A manifest is malformed. Always fatal — unknown provenance is never freshness."""


# ---------------------------------------------------------------------------- reading


def relative(name: str) -> str:
    """The repo-relative path of registry `name`."""
    return f"{POLICY_RELATIVE}/{REGISTRIES[name]}"


def path(name: str, root: Path = REPO_ROOT) -> Path:
    return root / relative(name)


def policy_files(root: Path = REPO_ROOT) -> list[Path]:
    """Every TOML file in the policy directory, registered here or not, in name order."""
    return sorted((root / POLICY_RELATIVE).glob("*.toml"))


def parse(text: str, where: str) -> dict:
    """`text` parsed, as a document the caller owns.

    Parsed once per distinct text and copied per call. A fingerprint reads the same
    registries once per unit, and parsing them again each time was most of what measuring
    cost; the copy keeps every caller's document its own, as a fresh parse would.
    """
    try:
        return copy.deepcopy(_parsed(text))
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"{where}: unparsable: {exc}") from exc


@functools.lru_cache(maxsize=32)
def _parsed(text: str) -> dict:
    return tomllib.loads(text)


def read(file: Path, where: str | None = None) -> dict:
    """The parsed TOML at `file`, which must exist. `where` names it in a refusal."""
    label = where or file.name
    if not file.is_file():
        raise ManifestError(f"{label}: missing")
    return parse(file.read_text(encoding="utf-8"), label)


def document(name: str, root: Path = REPO_ROOT, *, required: bool = False) -> dict:
    """Registry `name` parsed. An absent registry is empty unless `required`.

    Under the repository root it is read from the current source tree (`_tree.current()`),
    so a measurement of another commit reads that commit's registry; any other root is a
    scratch tree a selftest built, read from the filesystem.
    """
    if root == REPO_ROOT:
        import _tree

        tree = _tree.current()
        if not tree.is_file(relative(name)):
            if required:
                raise ManifestError(f"{relative(name)}: missing")
            return {}
        return parse(tree.read(relative(name)).decode("utf-8"), relative(name))
    file = path(name, root)
    if not file.is_file() and not required:
        return {}
    return read(file, relative(name))


def rows(name: str, table: str, root: Path = REPO_ROOT) -> list[dict]:
    """The `[[table]]` records of registry `name`; none when the registry is absent."""
    return document(name, root).get(table, [])


def text(name: str, root: Path = REPO_ROOT) -> str:
    """Registry `name` as committed text, for a reader that digests or quotes entries."""
    if root == REPO_ROOT:
        import _tree

        return _tree.text(relative(name))
    return path(name, root).read_text(encoding="utf-8")


def text_at(name: str, commit: str, root: Path = REPO_ROOT) -> str | None:
    """Registry `name` as it stands at `commit`, or None when `commit` does not hold it.

    Raises `ManifestError` when git cannot answer at all, because "the commit holds no
    registry" and "the question was not asked" are different facts.
    """
    blob = blob_at(relative(name), commit, root)
    return None if blob is None else blob.decode("utf-8")


def blob_at(rel: str, commit: str, root: Path = REPO_ROOT) -> bytes | None:
    """The bytes of repo-relative `rel` at `commit`, or None when `commit` does not hold it.

    Raises `ManifestError` when git cannot answer: `commit` does not resolve, `root` is not
    a repository, or `commit`'s tree names `rel` and its blob cannot be read. Only a commit
    that resolves, and whose tree has no entry for `rel`, can say the path is absent.
    """
    proc = subprocess.run(["git", "show", f"{commit}:{rel}"], cwd=root, capture_output=True)
    if proc.returncode == 0:
        return proc.stdout
    entry = subprocess.run(
        ["git", "ls-tree", "--full-tree", "--name-only", f"{commit}^{{commit}}", "--", rel],
        cwd=root,
        capture_output=True,
    )
    if entry.returncode == 0 and not entry.stdout.strip():
        return None
    reason = proc.stderr if entry.returncode == 0 else entry.stderr
    raise ManifestError(f"git show {commit}:{rel}: {reason.decode('utf-8', 'replace').strip()}")


def duplicate_ids(ids: list[str], label: str) -> list[str]:
    """One problem per id that more than one `label` record carries.

    An id is how a record is cited — in a review, an error message, a ledger row. Two
    records under one id are two decisions that cannot be told apart once cited.
    """
    seen: dict[str, int] = {}
    for key in ids:
        seen[key] = seen.get(key, 0) + 1
    return [
        f"{label} id {key} is carried by {count} records; give every record but the first a "
        f"fresh id"
        for key, count in sorted(seen.items())
        if count > 1
    ]
