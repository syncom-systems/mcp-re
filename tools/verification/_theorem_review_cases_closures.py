# SPDX-License-Identifier: Apache-2.0
"""Cases for premise closures.

Cases for `test_theorem_review.py`, which runs them.
"""

from __future__ import annotations

from _assumptions import (
    load_assumptions,
)
from _fingerprint import (
    Registries,
    fingerprint_unit,
    theorem_premises,
)
from _manifest import (
    load_verification,
)
from _theorem_review_support import (
    closure_fixture,
    premise_entry,
)
from _toolchain_lock import (
    load_toolchains,
)


def test_a_unit_scoped_premise_does_not_spread_to_every_unit_crossing_its_boundary():
    """Over-inclusion. The `boundary://` entry of a unit-scoped premise says which boundary
    it discharges FOR the units it names; a second unit crossing the same boundary does not
    thereby rest on it. Spread, a narrowed scope changed no closure."""
    named = premise_entry("ASM-N", ["unit://a", "boundary://boundary.k"])
    closure = closure_fixture(named)
    assert set(closure["THM-A"]) == {"ASM-N"}
    assert closure["THM-B"] == {}, closure["THM-B"]


def test_a_boundary_only_premise_attaches_to_every_unit_crossing_its_boundary():
    """Nothing narrower was stated, so every crosser rests on it."""
    wide = premise_entry("ASM-W", ["boundary://boundary.k"])
    closure = closure_fixture(wide)
    assert set(closure["THM-A"]) == {"ASM-W"}
    assert set(closure["THM-B"]) == {"ASM-W"}


def test_a_model_registration_is_in_no_closure_and_its_interpreter_is():
    """Ruling 39 §4: trust is attributed to the premise that gives the symbol its meaning."""
    giver = premise_entry("ASM-G", ["unit://a", "boundary://boundary.k"])
    registration = {
        "id": "ASM-R",
        "scope": ["unit://a", "boundary://boundary.k"],
        "premise_class": "model-registration",
        "interpreted_by": "ASM-G",
    }
    closure = closure_fixture(giver, registration)
    assert set(closure["THM-A"]) == {"ASM-G"}


WANTED_PREMISES = {
    "THM-0045": "ASM-0078",
    "THM-0083": "ASM-0083",
    "THM-0108": "ASM-0027",
    "THM-0117": "ASM-0076",
    "THM-0007": "ASM-0037",
}


def live_closures(wanted: dict) -> dict:
    """The premise closure of each `wanted` theorem, measured on the live registry."""
    from _theorems import load_theorems

    verification = load_verification()
    assumptions = load_assumptions()
    theorems = load_theorems(
        {unit["id"] for unit in verification.get("unit", [])},
        [e for e in verification.get("edge", []) if e.get("kind") == "PROOF_DEPENDENCY"],
    )
    rows = [r for r in theorems["theorem"] if r["id"] in wanted]
    units = {
        str(target).removeprefix("unit://") for row in rows for target in row.get("supported_by", [])
    }
    toolchains = load_toolchains()
    fps = {
        unit["id"]: fingerprint_unit(unit, Registries(verification, toolchains, assumptions))
        for unit in verification["unit"]
        if unit["id"] in units
    }
    return theorem_premises({"theorem": rows}, fps, assumptions)


def test_the_live_closures_take_the_repaired_premises_and_drop_the_registrations():
    """Under-inclusion is repaired by DATA: a premise names the unit that calls into its
    boundary. Measured on the live registry so a reverted scope is seen here."""
    closures = live_closures(WANTED_PREMISES)
    for theorem_id, premise in WANTED_PREMISES.items():
        assert premise in (closures[theorem_id] or {}), (theorem_id, closures[theorem_id])
    assert not any(
        asm in (closure or {}) for closure in closures.values() for asm in ("ASM-0074", "ASM-0075")
    )
