# SPDX-License-Identifier: Apache-2.0
"""The policy registries: the one reader of `verification/policy/`, and the one check of
the rule that keeps it the one reader.

THE FAILURE CLASS. The registries name each other. A mutation probe names a unit, a
theorem, a file and the text it weakens. A theorem names the units that support it. An
assumption names the units and boundaries it is scoped to and the seams it trusts. A
control disposition names a proposition. Each registry was opened raw by whichever tool
needed it, and each reference was checked late, by whichever lane happened to look: a
probe's anchor only by a suite asserting over live data, which checked the first site and
not the `also` sites; an assumption's site only by the assumptions lane, behind a path
filter; a disposition id by nothing, so eight ids were taken twice by parallel changes. A
registry edit therefore came with a remembered rule: run every suite.

So reading is owned once. `parse`, `read`, `document`, `rows`, `text`, `text_at` and
`blob_at` are the only code that turns a policy registry's bytes into data. The typed
loaders (`_manifest.load_verification`, `_theorems.load_theorems`, `_mutation.load_probes`,
`_structural.load_probes`, `_measured.load_measurements`, `_toolchains.load`) read through
them and add their own schema, and `reader_problems` refuses a reader around this module.
The same rule holds each generated table in `GENERATED_OWNERS` to the module that reads it.
The references between registries are checked by `_registry_refs`, which sits above the
typed loaders; `check-registries` runs both on the merge path.

Stdlib only, and it imports nothing from this package: every typed loader imports it.
"""

from __future__ import annotations

import ast
import re
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
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"{where}: unparsable: {exc}") from exc


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


# ---------------------------------------------------------------------------- the reader rule

#: Where a production reader can live: the gates and the assurance tooling.
_READER_ROOTS = ("scripts", "tools/verification")
_GUARDED_FILES = tuple(REGISTRIES[name] for name in sorted(GUARDED))
_POLICY_TAIL = re.compile(r"(?:^|/)verification/policy/?$")

#: Generated tables held to one reader the same way, each by the module that is its reader.
#: The owner may spell the path; every other production source asks the owner.
GENERATED_OWNERS = {"verification/generated/rust-targets.json": "_rust_targets.py"}


def _names_generated(value: str, exempt: frozenset[str]) -> bool:
    """A path-shaped string ending in a guarded generated table the source does not own."""
    if any(ch.isspace() for ch in value):
        return False
    return any(value.endswith(rel) for rel in GENERATED_OWNERS if rel not in exempt)


def _production_sources(root: Path) -> list[Path]:
    out: list[Path] = []
    for base in _READER_ROOTS:
        for file in sorted((root / base).iterdir()) if (root / base).is_dir() else []:
            if not file.is_file() or file.name.startswith("test_") or file.name == "_registries.py":
                continue
            if file.suffix == ".py":
                out.append(file)
            elif not file.suffix and file.read_bytes()[:64].startswith(b"#!") and b"python" in file.read_bytes()[:64]:
                out.append(file)
    return out


def _docstrings(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


def _names_registry(value: str) -> bool:
    """A path-shaped string naming a guarded registry.

    The bare directory is not judged as a string: `startswith("verification/policy/")`
    classifies a changed path, which is not a read. Built into a path it is judged, below.
    """
    if any(ch.isspace() for ch in value):
        return False
    return "/" in value and value.endswith(_GUARDED_FILES)


def _div_chain(node: ast.AST) -> list[str]:
    """The string constants of a `a / "b" / "c"` path expression, left to right."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _div_chain(node.left) + _div_chain(node.right)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Path" and node.args:
        return _div_chain(node.args[0])
    return []


def source_problems(source: str, label: str) -> list[str]:
    """Where `source` spells a guarded registry's path instead of asking this module.

    A path to the policy directory, or to a guarded registry, written as a string or built
    with `/`. Prose is not a reader: a docstring, or a string with whitespace in it, is a
    sentence about a registry rather than a path to one.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"{label}: unreadable Python ({exc.msg}, line {exc.lineno})"]
    skip = _docstrings(tree)
    # Only a whole path expression is judged: `a / "verification" / "policy"` is the left
    # operand of `... / "toolchains.lock.toml"`, and is not a path of its own there.
    inner = {
        id(node.left)
        for node in ast.walk(tree)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
    }
    exempt = frozenset(rel for rel, owner in GENERATED_OWNERS.items() if Path(label).name == owner)
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and id(node) not in inner:
            parts = _div_chain(node)
            joined = "/".join(part.strip("/") for part in parts)
            if parts and (
                _POLICY_TAIL.search(joined)
                or ("verification/policy/" in joined and joined.endswith(_GUARDED_FILES))
                or _names_generated(joined, exempt)
            ):
                out.append(f"{label}:{node.lineno}: builds the path {joined!r}")
        elif isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Path" and node.args:
            parts = _div_chain(node.args[0])
            if len(parts) == 1 and (_POLICY_TAIL.search(parts[0]) or _names_generated(parts[0], exempt)):
                out.append(f"{label}:{node.lineno}: builds the path {parts[0]!r}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            if _names_registry(node.value) or _names_generated(node.value, exempt):
                out.append(f"{label}:{node.lineno}: names the path {node.value!r}")
    return sorted(set(out))


def reader_problems(root: Path = REPO_ROOT) -> list[str]:
    """Every production reader that reaches a guarded registry around this module, or a
    guarded generated table around its owner."""
    out: list[str] = []
    for file in _production_sources(root):
        label = file.relative_to(root).as_posix()
        out += source_problems(file.read_text(encoding="utf-8"), label)
    return out
