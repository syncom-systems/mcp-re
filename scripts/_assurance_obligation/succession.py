# SPDX-License-Identifier: Apache-2.0
"""SUCCESSION: the one way the registry's row count may rise, and the clauses that bound it."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from _assurance_obligation.config import REPO, UNITS_REL
from _assurance_obligation.registry import severity_rank


@dataclass(frozen=True)
class Basis:
    """What the registry is judged against: the base revision's rows and unit paths, this
    tree's unit paths, and the tree whose files a `decomposition_ref` must name."""

    before: dict[str, dict] | None
    base_paths: dict[str, set[str]] | None = None
    now_paths: dict[str, set[str]] = field(default_factory=dict)
    repo: Path = REPO


@dataclass(frozen=True)
class Ground:
    """The registry, the measured population and the basis one succession is checked in."""

    registry: dict[str, dict]
    measured: dict[str, dict]
    basis: Basis


@dataclass(frozen=True)
class Claim:
    """One row asserting that it succeeds `predecessor`, recorded in `reference`."""

    unit: str
    row: dict
    predecessor: str
    reference: str


def _one_half(ground: Ground, claim: Claim) -> str | None:
    if claim.predecessor and claim.reference:
        return None
    return (
        f"registry row for {claim.unit!r} declares only one half of a succession "
        f"(succeeds={claim.predecessor!r}, decomposition_ref={claim.reference!r}). A succession "
        f"is an obligation refined over recorded reasoning: both halves, or neither."
    )


def _reference_missing(ground: Ground, claim: Claim) -> str | None:
    if (ground.basis.repo / claim.reference).is_file():
        return None
    return (
        f"registry row for {claim.unit!r} names decomposition_ref {claim.reference!r}, which "
        f"this tree does not hold. A decomposition points at its record rather than "
        f"at a memory of one."
    )


def _succeeds_itself(ground: Ground, claim: Claim) -> str | None:
    if claim.predecessor != claim.unit:
        return None
    return (
        f"registry row for {claim.unit!r} succeeds itself. A succession replaces one "
        f"proposition with narrower ones; a row that is its own predecessor records "
        f"no decomposition and would renew its own authorization every merge."
    )


def _predecessor_still_owes(ground: Ground, claim: Claim) -> str | None:
    in_registry = claim.predecessor in ground.registry
    if not (in_registry or claim.predecessor in ground.measured):
        return None
    return (
        f"registry row for {claim.unit!r} succeeds {claim.predecessor!r}, which still owes: it "
        f"is {'in the registry' if in_registry else 'measured as owing'}."
        f" A predecessor that still exists keeps its own row and is succeeded by "
        f"nothing — otherwise one obligation would be registered twice."
    )


def _base_unavailable(ground: Ground, claim: Claim) -> str | None:
    if ground.basis.before is not None:
        return None
    return (
        f"registry row for {claim.unit!r} claims succession from {claim.predecessor!r}, and the "
        f"base revision is unavailable, so it cannot be checked. A succession is an "
        f"authorization against the base; an uncheckable one is refused rather than "
        f"assumed."
    )


def _predecessor_not_in_base(ground: Ground, claim: Claim) -> str | None:
    if claim.predecessor in (ground.basis.before or {}):
        return None
    return (
        f"registry row for {claim.unit!r} succeeds {claim.predecessor!r}, which the base "
        f"registry does not hold. Succession refines an obligation that already "
        f"existed — it cannot invent one, and an authorization spent by an earlier "
        f"merge names nothing here."
    )


def _severity_raised(ground: Ground, claim: Claim) -> str | None:
    ceiling = (ground.basis.before or {})[claim.predecessor].get("effective_severity")
    mine = claim.row.get("effective_severity")
    if severity_rank(str(mine)) <= severity_rank(str(ceiling)):
        return None
    return (
        f"registry row for {claim.unit!r} succeeds {claim.predecessor!r} at effective severity "
        f"{mine!r}, above the predecessor's {ceiling!r}. A decomposition may state "
        f"an obligation more precisely; it may not raise what is at stake."
    )


def _base_paths_unavailable(ground: Ground, claim: Claim) -> str | None:
    if ground.basis.base_paths is not None:
        return None
    return (
        f"registry row for {claim.unit!r} claims succession from {claim.predecessor!r}, and "
        f"{UNITS_REL} is unavailable at the base, so the production code the "
        f"obligation covers cannot be compared."
    )


def _paths_widened(ground: Ground, claim: Claim) -> str | None:
    basis = ground.basis
    widened = sorted(
        basis.now_paths.get(claim.unit, set()) - (basis.base_paths or {}).get(claim.predecessor, set())
    )
    if not widened:
        return None
    return (
        f"registry row for {claim.unit!r} succeeds {claim.predecessor!r} but declares path(s) "
        f"{widened} the predecessor did not cover. A succession refines an "
        f"obligation over the SAME production code; new code does not ride one."
    )


#: The clauses, in the order they are asked. The first that fails is the row's defect, and a
#: row that fails none is excused.
CLAUSES = (
    _one_half,
    _reference_missing,
    _succeeds_itself,
    _predecessor_still_owes,
    _base_unavailable,
    _predecessor_not_in_base,
    _severity_raised,
    _base_paths_unavailable,
    _paths_widened,
)


def _claim(unit: str, row: dict) -> Claim | None:
    predecessor = str(row.get("succeeds") or "").strip()
    reference = str(row.get("decomposition_ref") or "").strip()
    if not predecessor and not reference:
        return None
    return Claim(unit, row, predecessor, reference)


def _spent_by_its_own_merge(basis: Basis, unit: str) -> bool:
    """The row is in the base, so it is an ordinary pre-existing obligation and its
    succession fields are provenance rather than authority. Re-validating them would fail
    every merged decomposition forever, against a predecessor its own merge removed."""
    return basis.before is not None and unit in basis.before


def _first_defect(ground: Ground, claim: Claim) -> str | None:
    for clause in CLAUSES:
        defect = clause(ground, claim)
        if defect is not None:
            return defect
    return None


def succession_defects(
    registry: dict[str, dict], measured: dict[str, dict], basis: Basis
) -> tuple[list[str], set[str]]:
    """Validate every row claiming succession; return its defects and the rows it excuses.

    A row is EXCUSED from the shrink-only rule only if it survives every clause here, so a
    malformed succession does not both fail and buy growth.
    """
    ground = Ground(registry, measured, basis)
    found: list[str] = []
    excused: set[str] = set()
    for unit in sorted(registry):
        claim = _claim(unit, registry[unit])
        if claim is None or _spent_by_its_own_merge(basis, unit):
            continue
        defect = _first_defect(ground, claim)
        if defect is None:
            excused.add(unit)
        else:
            found.append(defect)
    return found, excused
