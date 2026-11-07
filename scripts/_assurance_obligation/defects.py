# SPDX-License-Identifier: Apache-2.0
"""Every way the registry and the measured obligations disagree."""

from __future__ import annotations

import _ratchet

from _assurance_obligation.config import REVIEWED
from _assurance_obligation.succession import Basis, succession_defects

SEVERITY_FIELDS = ("effective_severity", "direct_consequence_severity", "inherited_severity")


def _unregistered(measured: dict[str, dict], registry: dict[str, dict]) -> list[str]:
    return [
        f"unit {unit!r} owes a falsifier under N1 (effective severity "
        f"{measured[unit]['effective_severity']!r}) and is not in the registry. The "
        f"migration ratchet is CLOSED to new work: a proposition that gains an "
        f"obligation by being added, reclassified, or raised in severity discharges it "
        f"or fails. Register a `mutation://` falsifier that attacks its production "
        f"property, or reclassify the proposition into a class whose mechanics it "
        f"actually satisfies."
        for unit in sorted(set(measured) - set(registry))
    ]


def _dead_rows(measured: dict[str, dict], registry: dict[str, dict]) -> list[str]:
    return [
        f"registry row for {unit!r} names an obligation that is no longer owed — the "
        f"unit has a falsifier, has been reclassified, has dropped below Medium, or no "
        f"longer exists. Remove the row. A dead row hides the next live one."
        for unit in sorted(set(registry) - set(measured))
    ]


def _moved_severity(unit: str, row: dict, now: dict) -> list[str]:
    return [
        f"registry row for {unit!r} records {field} {row.get(field)!r} but the "
        f"graph now derives {now[field]!r}. The obligation is not the one this "
        f"row covers. A materially changed proposition may not ride an existing "
        f"entry: discharge it, or correct the row only when the change is a "
        f"derivation correction rather than a new obligation."
        for field in SEVERITY_FIELDS
        if row.get(field) != now[field]
    ]


def _stale_reachability(unit: str, row: dict, now: dict) -> list[str]:
    if row.get("root_reachable") == now["root_reachable"]:
        return []
    return [
        f"registry row for {unit!r} records root_reachable "
        f"{row.get('root_reachable')!r} but the graph now says "
        f"{now['root_reachable']!r}. Reachability is a derived fact and the row "
        f"must state the current one — it changes nothing about the obligation, "
        f"and a stale copy of it is a reader's false premise."
    ]


def _drifted_rows(measured: dict[str, dict], registry: dict[str, dict]) -> list[str]:
    found: list[str] = []
    for unit in sorted(set(measured) & set(registry)):
        row, now = registry[unit], measured[unit]
        found += _moved_severity(unit, row, now)
        found += _stale_reachability(unit, row, now)
    return found


def _grown(registry: dict[str, dict], before: dict[str, dict], excused: set[str]) -> list[str]:
    added = sorted(set(registry) - set(before) - excused)
    if not added:
        return []
    return [
        f"the registry GREW against the base: {added}. It may only shrink — the "
        f"population it bounds was fixed at the baseline, and a registry that can grow "
        f"is a waiver with extra steps. The one exception is SUCCESSION, and these rows "
        f"do not carry a valid one: a decomposition of an obligation the base registry "
        f"held names it in `succeeds` beside the `decomposition_ref` that records it."
    ]


def _returned_to_unreviewed(before: dict[str, dict], registry: dict[str, dict]) -> list[str]:
    found: list[str] = []
    for unit, was_row, row in _ratchet.transitions(before, registry):
        was, now = was_row.get("status"), row.get("status")
        if now == "unreviewed" and was in REVIEWED:
            found.append(
                f"registry row for {unit!r} returned to 'unreviewed' from {was!r}. The "
                f"lifecycle is one-way: nothing that has been investigated becomes "
                f"uninvestigated."
            )
    return found


def defects(measured: dict[str, dict], registry: dict[str, dict], basis: Basis) -> list[str]:
    """Every way the registry and the measured obligations disagree."""
    succession, excused = succession_defects(registry, measured, basis)
    found = list(succession)
    found += _unregistered(measured, registry)
    found += _dead_rows(measured, registry)
    found += _drifted_rows(measured, registry)
    if basis.before is None:
        return found
    found += _grown(registry, basis.before, excused)
    found += _returned_to_unreviewed(basis.before, registry)
    return found
