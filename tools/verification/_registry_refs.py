# SPDX-License-Identifier: Apache-2.0
"""The references between the policy registries, checked once.

THE FAILURE CLASS. The registries name each other. A mutation probe names a unit, a
theorem, a file and the text it weakens. A theorem names the units that support it. An
assumption names the units and boundaries it is scoped to and the seams it trusts. Each
reference was checked late, by whichever lane happened to look, so a registry edit came
with a remembered rule: run every suite.

`load` runs every typed loader once, `reference_problems` checks every reference from one
registry into another or into the tree, and `named_paths` is every repository path a
registry names, with the record that names it. `check-registries` runs both on the merge
path.

This module sits above the typed loaders and imports them; `_registries`, which they all
read through, imports nothing back.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from _manifest import load_verification
from _assumptions import load_assumptions
from _boundary_crossings import expand_paths
from _trust_boundaries import load_trust_boundaries
from _measured import declaration_problems, load_measurements
from _mutation import load_probes as load_mutation_probes
from _mutation import undeclared_expectations, weaken
from _registries import REPO_ROOT, ManifestError, path
from _seams import live_sites, stale_sites
from _structural import load_probes as load_structural_probes
from _structural import provenance_problem
from _theorems import load_theorems


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
    #: Every seam site the tree declares, as `_seams.live_sites` resolves one.
    live_sites: frozenset[str]


def load(root: Path = REPO_ROOT) -> Registries:
    """Every registry through its typed loader. A malformed registry raises `ManifestError`."""
    verification = load_verification()
    units = {unit["id"]: unit for unit in verification.get("unit", [])}
    theorems = load_theorems(
        set(units), [e for e in verification.get("edge", []) if e.get("kind") == "PROOF_DEPENDENCY"]
    )
    assumptions = load_assumptions()
    boundaries = load_trust_boundaries()
    return Registries(
        units=units,
        theorems=theorems.get("theorem", []),
        assumptions=assumptions.get("assumption", []),
        boundaries=frozenset(entry["id"] for entry in boundaries.get("boundary", [])),
        mutation_probes=load_mutation_probes(root),
        structural_probes=load_structural_probes(path("structural-probes", root)),
        measurements=load_measurements(path("measurements", root)),
        live_sites=frozenset(live_sites(verification, assumptions, root)),
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


def _probe_problems(unit: dict, probe: dict, theorems_on_unit: set[str], root: Path) -> list[str]:
    """What is wrong with one mutation probe whose unit is declared."""
    where = f"mutation probe {probe['id']}"
    out: list[str] = []
    theorem = probe.get("theorem")
    if theorem and theorem not in theorems_on_unit:
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


def _mutation_problems(reg: Registries, root: Path) -> list[str]:
    out: list[str] = []
    resting = _resting(reg.theorems)
    for probe in reg.mutation_probes:
        unit = reg.units.get(probe["unit"])
        if unit is None:
            out.append(f"mutation probe {probe['id']}: unit {probe['unit']!r} is not declared "
                       "in verification.toml")
        else:
            out += _probe_problems(unit, probe, resting.get(probe["unit"], set()), root)
    return out


def _structural_problem(unit: dict, probe: dict, root: Path) -> str | None:
    """What is wrong with one structural probe whose unit is declared."""
    where = f"structural probe {probe['id']}"
    if not any(str(e).startswith("structural://") for e in unit.get("evidence", [])):
        return (
            f"{where}: unit {probe['unit']!r} declares no structural:// evidence, so the "
            f"refusal it witnesses is one no claim rests on and no fingerprint covers"
        )
    problem = provenance_problem(probe, unit, root)
    return f"{where}: {problem}" if problem else None


def _structural_problems(reg: Registries, root: Path) -> list[str]:
    out: list[str] = []
    for probe in reg.structural_probes:
        unit = reg.units.get(probe["unit"])
        if unit is None:
            out.append(f"structural probe {probe['id']}: unit {probe['unit']!r} is not "
                       "declared in verification.toml")
            continue
        problem = _structural_problem(unit, probe, root)
        if problem:
            out.append(problem)
    return out


def _scope_problem(reg: Registries, entry: dict, target: str) -> str | None:
    kind, _, ident = target.partition("://")
    if kind == "unit" and ident not in reg.units:
        return (
            f"assumption {entry['id']}: scope {target} names a unit no [[unit]] "
            f"declares, so the premise reaches no fingerprint while reading as scoped"
        )
    if kind == "boundary" and ident not in reg.boundaries:
        return (
            f"assumption {entry['id']}: scope {target} names a boundary "
            f"trust-boundaries.toml does not declare"
        )
    return None


def _assumption_problems(reg: Registries) -> list[str]:
    scopes = (
        _scope_problem(reg, entry, str(target))
        for entry in reg.assumptions
        for target in entry.get("scope", [])
    )
    out = [problem for problem in scopes if problem]
    for asm_id, gone in stale_sites(reg.assumptions, reg.live_sites).items():
        out += [
            f"assumption {asm_id}: site {site} names no seam the tree declares. A site "
            f"that stopped resolving records trust in code that was renamed or removed; "
            f"discharge the entry or point it at the seam that replaced it."
            for site in gone
        ]
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
    out += declaration_problems(reg.units, reg.measurements)
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


def _unit_paths(reg: Registries) -> Iterator[tuple[str, str]]:
    for unit_id, unit in reg.units.items():
        for file in expand_paths(unit.get("paths", [])):
            yield file, f"unit:{unit_id}"


def _probe_paths(reg: Registries) -> Iterator[tuple[str, str]]:
    for probe in reg.mutation_probes:
        for site in [probe, *probe.get("also", [])]:
            yield str(site["path"]), f"mutation-probe:{probe['id']}"


def _structural_paths(reg: Registries) -> Iterator[tuple[str, str]]:
    for file, owners in structural_probe_paths(reg.structural_probes).items():
        for owner in owners:
            yield file, owner


def _assumption_paths(reg: Registries) -> Iterator[tuple[str, str]]:
    for entry in reg.assumptions:
        for site in entry.get("sites", []):
            yield str(site).partition("#")[0], f"assumption:{entry['id']}"


def named_paths(reg: Registries) -> dict[str, frozenset[str]]:
    """Every repository file a registry names, mapped to the records that name it.

    A unit's `paths` are expanded globs. An owner is `<kind>:<id>`.
    """
    found: dict[str, set[str]] = {}
    for source in (_unit_paths, _probe_paths, _structural_paths, _assumption_paths):
        for file, owner in source(reg):
            _add(found, file, owner)
    return {file: frozenset(owners) for file, owners in sorted(found.items())}
