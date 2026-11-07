# SPDX-License-Identifier: Apache-2.0
"""Registration: which `(mechanism, site)` pairs the assumptions registry accounts for per
unit, and whether one seam is among them."""

from __future__ import annotations

def registered_by_unit(assumptions: dict) -> dict[str, set[tuple[str, str]]]:
    """`(mechanism kind, SITE)` pairs the registry accounts for, per unit in `scope`.

    Scope is what makes registration mean something, and the SITE is what makes it mean one
    thing. `verus:external_body` trusted inside `core.time_rfc3339` is a statement about
    that unit's trusted computing base and no other; collapsing the registry to a set of
    names would hand every unit in the repository whatever any one assumption happened to
    need. Kind-level registration inside a unit had the same defect one level down —
    R9-C037 / R9-C067 / R9-C068: `scope` names whole crates, so one entry licensed every
    present and future site of that mechanism in every file those units declare. The
    registry recorded *"this unit trusts uninterpreted spec functions"*, which is not a fact
    about any seam.

    An assumption with NO `sites` therefore registers NOTHING. That is the fail-closed
    direction and the only one available: the alternative — absent means all — is the rule
    being replaced.
    """
    out: dict[str, set[tuple[str, str]]] = {}
    for entry in assumptions.get("assumption", []):
        mechanism = entry["tool_specific_mechanism"].split(":", 1)[-1]
        sites = [str(site) for site in entry.get("sites", [])]
        for target in entry.get("scope", []):
            target = str(target)
            if target.startswith("unit://"):
                unit_id = target.removeprefix("unit://")
                out.setdefault(unit_id, set()).update((mechanism, site) for site in sites)
    return out


def is_registered(
    mechanism: str,
    site: str | None,
    owners: frozenset[str] | set[str],
    registered: dict[str, set[tuple[str, str]]],
) -> bool:
    """Is THIS SEAM registered by an assumption scoped to a unit that declares its file?

    Three conjuncts, and each one is a way registration could say more than it means: the
    MECHANISM, because trusting an uninterpreted spec function is not trusting an
    `external_body`; the UNIT, because a trusted computing base belongs to the unit whose
    proofs rest on it; and the SITE, because a seam is a place a proof stops proving, and
    the registry is a statement about places.

    A file no unit declares has no owning trusted computing base, so nothing can register a
    mechanism there — which is why the empty owner set answers no rather than yes. A seam
    whose item cannot be named (`site is None`) is likewise unregistrable: it has no
    identity to register.
    """
    if site is None:
        return False
    return any((mechanism, site) in registered.get(unit_id, set()) for unit_id in owners)
