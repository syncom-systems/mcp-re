# SPDX-License-Identifier: Apache-2.0
"""The unit-to-assumption direction, derived from `[[assumption]].scope`."""

from __future__ import annotations




def unit_assumptions(unit_id: str, assumptions: dict) -> list[str]:
    """The assumptions a unit trusts, derived from `[[assumption]].scope`.

    ADR-MCPRE-059 §8 has one authoritative direction, and this is the only place the
    inverse is computed. `scope` is the authoritative side because the assumption owns its
    own trust blast radius and can name a boundary as readily as a unit; every consumer —
    the review packet, the owner and blast-radius views, the evidence graph — derives the
    unit→assumption direction here.

    A second authored declaration on the unit is not a convenience, it is a second source:
    the two halves feed different machinery, `scope` reaching the fingerprint and
    `check-assumptions` while a unit-side field would reach only the human-facing artefacts.
    A premise no scope names is absent from the unit's fingerprint, so the assumption can be
    rewritten and every claim over that unit still reads as fresh.
    """
    prefix = f"unit://{unit_id}"
    return sorted(
        entry["id"]
        for entry in assumptions.get("assumption", [])
        if prefix in [str(target) for target in entry.get("scope", [])]
    )


def assumption_scope_defects(verification: dict, assumptions: dict) -> list[str]:
    """Scopes that name a unit no `[[unit]]` declares.

    What remains checkable once the relation has one source. A scope entry naming a unit
    that does not exist reads as a registration and trusts the assumption nowhere: the
    premise reaches no fingerprint, no view and no packet, while the registry shows the
    assumption as scoped. Misspelling a unit id is exactly how a premise silently stops
    being carried.

    The disagreement control this replaces had a second job — catching a unit that
    declared an unregistered assumption — and the schema now does that one: `assumptions`
    is no longer an admissible `[[unit]]` key, so there is no unit-side declaration left to
    be wrong.
    """
    known_units = {unit["id"] for unit in verification.get("unit", [])}
    defects: list[str] = []
    for entry in assumptions.get("assumption", []):
        for target in entry.get("scope", []):
            target = str(target)
            if not target.startswith("unit://"):
                continue
            unit_id = target.removeprefix("unit://")
            if unit_id not in known_units:
                defects.append(
                    f"assumption {entry['id']} is scoped to unit://{unit_id}, which no "
                    f"[[unit]] declares. A scope naming a unit that does not exist trusts "
                    f"the assumption nowhere while reading as a registration."
                )
    return defects
