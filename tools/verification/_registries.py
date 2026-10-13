# SPDX-License-Identifier: Apache-2.0
"""The policy registries: the one reader of `verification/policy/`, and the one check of
the references between its registries.

THE FAILURE CLASS. The registries name each other. A mutation probe names a unit, a
theorem, a file and the text it weakens. A theorem names the units that support it. An
assumption names the units and boundaries it is scoped to and the seams it trusts. A
control disposition names a proposition. Each registry was opened raw by whichever tool
needed it, and each reference was checked late, by whichever lane happened to look: a
probe's anchor only by a suite asserting over live data, which checked the first site and
not the `also` sites; an assumption's site only by the assumptions lane, behind a path
filter; a disposition id by nothing, so eight ids were taken twice by parallel changes. A
registry edit therefore came with a remembered rule: run every suite.

So this module owns two things.

  * READING. `parse`, `read`, `document`, `rows`, `text`, `text_at` and `blob_at` are the
    only code that turns a policy registry's bytes into data. The typed loaders
    (`_manifest.load_verification`, `_theorems.load_theorems`, `_mutation.load_probes`,
    `_structural.load_probes`, `_measured.load_measurements`, `_toolchains.load`) read
    through them and add their own schema.
  * REFERENCES. `load` runs every typed loader once, `reference_problems` checks every
    reference from one registry into another or into the tree, and `named_paths` is every
    repository path a registry names, with the record that names it. `check-registries`
    runs both on the merge path, and `reader_problems` keeps the first half true.

Stdlib only at import. The reference checks import the typed loaders when they run,
because those loaders import this module.
"""

from __future__ import annotations

import ast
import re
import subprocess
import tomllib
from dataclasses import dataclass
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
    """Registry `name` parsed. An absent registry is empty unless `required`."""
    file = path(name, root)
    if not file.is_file() and not required:
        return {}
    return read(file, relative(name))


def rows(name: str, table: str, root: Path = REPO_ROOT) -> list[dict]:
    """The `[[table]]` records of registry `name`; none when the registry is absent."""
    return document(name, root).get(table, [])


def text(name: str, root: Path = REPO_ROOT) -> str:
    """Registry `name` as committed text, for a reader that digests or quotes entries."""
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


# ---------------------------------------------------------------------------- references


@dataclass(frozen=True)
class Registries:
    """Every registry, each through its typed loader, plus the seam sites the tree declares."""

    units: dict[str, dict]
    theorems: list[dict]
    assumptions: list[dict]
    boundaries: frozenset[str]
    mutation_probes: list[dict]
    structural_probes: list[dict]
    measurements: list[dict]
    #: Every seam site the tree declares, as `check-assumptions` resolves one.
    live_sites: frozenset[str]


def load(root: Path = REPO_ROOT) -> Registries:
    """Every registry through its typed loader. A malformed registry raises `ManifestError`."""
    from _load_tool import load_tool
    from _manifest import load_assumptions, load_trust_boundaries, load_verification
    from _measured import load_measurements
    from _mutation import load_probes as load_mutation_probes
    from _structural import load_probes as load_structural_probes
    from _theorems import load_theorems

    verification = load_verification()
    units = {unit["id"]: unit for unit in verification.get("unit", [])}
    theorems = load_theorems(
        set(units), [e for e in verification.get("edge", []) if e.get("kind") == "PROOF_DEPENDENCY"]
    )
    assumptions = load_assumptions()
    boundaries = load_trust_boundaries()
    seams = load_tool("check-assumptions", "check_assumptions")
    return Registries(
        units=units,
        theorems=theorems.get("theorem", []),
        assumptions=assumptions.get("assumption", []),
        boundaries=frozenset(entry["id"] for entry in boundaries.get("boundary", [])),
        mutation_probes=load_mutation_probes(root),
        structural_probes=load_structural_probes(path("structural-probes", root)),
        measurements=load_measurements(path("measurements", root)),
        live_sites=frozenset(seams.live_sites()),
    )


def _resting(theorems: list[dict]) -> dict[str, set[str]]:
    """Unit id -> the theorems that rest on it, as owner or as `supported_by`."""
    out: dict[str, set[str]] = {}
    for row in theorems:
        supporters = [str(ref).removeprefix("unit://") for ref in row.get("supported_by", [])]
        for unit in [*supporters, str(row.get("owner", ""))]:
            if unit:
                out.setdefault(unit, set()).add(row["id"])
    return out


def _mutation_problems(reg: Registries, root: Path) -> list[str]:
    from _mutation import undeclared_expectations, weaken

    out: list[str] = []
    resting = _resting(reg.theorems)
    for probe in reg.mutation_probes:
        where = f"mutation probe {probe['id']}"
        unit = reg.units.get(probe["unit"])
        if unit is None:
            out.append(f"{where}: unit {probe['unit']!r} is not declared in verification.toml")
            continue
        theorem = probe.get("theorem")
        if theorem and theorem not in resting.get(probe["unit"], set()):
            out.append(
                f"{where}: theorem {theorem} does not rest on unit {probe['unit']!r}. The probe "
                f"defends a conjunct of the theorem it names; naming another states that a "
                f"different proposition is protected."
            )
        unknown = undeclared_expectations(unit, probe)
        if unknown:
            out.append(f"{where}: expect_red names {unknown}, which the unit does not declare")
        try:
            weaken(root, probe, where)
        except ManifestError as exc:
            out.append(str(exc))
    return out


def _structural_problems(reg: Registries, root: Path) -> list[str]:
    from _structural import provenance_problem

    out: list[str] = []
    for probe in reg.structural_probes:
        where = f"structural probe {probe['id']}"
        unit = reg.units.get(probe["unit"])
        if unit is None:
            out.append(f"{where}: unit {probe['unit']!r} is not declared in verification.toml")
            continue
        problem = provenance_problem(probe, unit, root)
        if problem:
            out.append(f"{where}: {problem}")
    return out


def stale_sites(assumptions: list[dict], live: set[str] | frozenset[str]) -> dict[str, list[str]]:
    """Assumption id -> the registered sites that name no seam in `live`.

    A site key is derived from the ITEM a seam sits on, so it survives formatting but not a
    rename or a deletion. An entry left pointing at a seam that no longer exists reads as
    trust the tree no longer needs.
    """
    out: dict[str, list[str]] = {}
    for entry in assumptions:
        gone = sorted({str(site) for site in entry.get("sites", [])} - set(live))
        if gone:
            out[entry["id"]] = gone
    return out


def _assumption_problems(reg: Registries) -> list[str]:
    out: list[str] = []
    for entry in reg.assumptions:
        for target in (str(t) for t in entry.get("scope", [])):
            kind, _, ident = target.partition("://")
            if kind == "unit" and ident not in reg.units:
                out.append(
                    f"assumption {entry['id']}: scope {target} names a unit no [[unit]] "
                    f"declares, so the premise reaches no fingerprint while reading as scoped"
                )
            if kind == "boundary" and ident not in reg.boundaries:
                out.append(
                    f"assumption {entry['id']}: scope {target} names a boundary "
                    f"trust-boundaries.toml does not declare"
                )
    for asm_id, gone in stale_sites(reg.assumptions, reg.live_sites).items():
        for site in gone:
            out.append(
                f"assumption {asm_id}: site {site} names no seam the tree declares. A site "
                f"that stopped resolving records trust in code that was renamed or removed; "
                f"discharge the entry or point it at the seam that replaced it."
            )
    return out


def reference_problems(reg: Registries, root: Path = REPO_ROOT) -> list[str]:
    """Every reference from one registry into another, or into the tree, that does not hold."""
    out = _mutation_problems(reg, root)
    out += _structural_problems(reg, root)
    out += [
        f"measurement {m['id']}: unit {m['unit']!r} is not declared in verification.toml"
        for m in reg.measurements
        if m["unit"] not in reg.units
    ]
    out += _assumption_problems(reg)
    return out


def _add(found: dict[str, set[str]], file: str, owner: str) -> None:
    found.setdefault(file, set()).add(owner)


def structural_probe_paths(probes: list[dict]) -> dict[str, set[str]]:
    """The files a structural probe reads: its injection parent, its documented case, and
    every file its relaxation edits."""
    found: dict[str, set[str]] = {}
    for probe in probes:
        owner = f"structural-probe:{probe.get('id')}"
        for key in ("insertion_parent", "doc_path"):
            if probe.get(key):
                _add(found, str(probe[key]), owner)
        for edit in probe.get("relaxation", []):
            _add(found, str(edit["path"]), owner)
    return found


def named_paths(reg: Registries) -> dict[str, frozenset[str]]:
    """Every repository file a registry names, mapped to the records that name it.

    A unit's `paths` are expanded globs. An owner is `<kind>:<id>`.
    """
    from _manifest import expand_paths

    found: dict[str, set[str]] = {}
    for unit_id, unit in reg.units.items():
        for file in expand_paths(unit.get("paths", [])):
            _add(found, file, f"unit:{unit_id}")
    for probe in reg.mutation_probes:
        for site in [probe, *probe.get("also", [])]:
            _add(found, str(site["path"]), f"mutation-probe:{probe['id']}")
    for file, owners in structural_probe_paths(reg.structural_probes).items():
        for owner in owners:
            _add(found, file, owner)
    for entry in reg.assumptions:
        for site in entry.get("sites", []):
            _add(found, str(site).partition("#")[0], f"assumption:{entry['id']}")
    return {file: frozenset(owners) for file, owners in sorted(found.items())}


# ---------------------------------------------------------------------------- the reader rule

#: Where a production reader can live: the gates and the assurance tooling.
_READER_ROOTS = ("scripts", "tools/verification")
_GUARDED_FILES = tuple(REGISTRIES[name] for name in sorted(GUARDED))
_POLICY_TAIL = re.compile(r"(?:^|/)verification/policy/?$")


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
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and id(node) not in inner:
            parts = _div_chain(node)
            joined = "/".join(part.strip("/") for part in parts)
            if parts and (_POLICY_TAIL.search(joined) or ("verification/policy/" in joined and joined.endswith(_GUARDED_FILES))):
                out.append(f"{label}:{node.lineno}: builds the path {joined!r}")
        elif isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Path" and node.args:
            parts = _div_chain(node.args[0])
            if len(parts) == 1 and _POLICY_TAIL.search(parts[0]):
                out.append(f"{label}:{node.lineno}: builds the path {parts[0]!r}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            if _names_registry(node.value):
                out.append(f"{label}:{node.lineno}: names the path {node.value!r}")
    return sorted(set(out))


def reader_problems(root: Path = REPO_ROOT) -> list[str]:
    """Every production reader that reaches a guarded registry around this module."""
    out: list[str] = []
    for file in _production_sources(root):
        label = file.relative_to(root).as_posix()
        out += source_problems(file.read_text(encoding="utf-8"), label)
    return out
