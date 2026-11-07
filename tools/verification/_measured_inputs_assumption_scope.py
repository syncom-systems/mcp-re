# SPDX-License-Identifier: Apache-2.0
"""The assumption relation has ONE authoritative direction: an assumption's `scope` names its units, and a unit cannot declare its own."""

from __future__ import annotations

from _assumption_scope import assumption_scope_defects, unit_assumptions
from _measured_inputs_support import (
    ASSUMPTIONS,
    DOC,
    UNITS,
    components,
    measure,
)


def test_an_assumptions_content_participates_not_only_its_id():
    """Recording ids alone let an assumption be rewritten — its description widened, its
    mechanism swapped — without any unit deriving DIRTY_ASSUMPTION."""
    trusted = components("core.time_rfc3339")["trusted_assumptions"]
    assert set(trusted) == {"ASM-0001", "ASM-0002", "ASM-0003", "ASM-0004"}
    assert all(digest.startswith("sha256:") for digest in trusted.values())

    widened = {
        "assumption": [
            dict(entry, description="anything at all")
            for entry in ASSUMPTIONS.get("assumption", [])
        ]
    }
    after = measure(UNITS["core.time_rfc3339"], assumptions=widened)
    assert after["components"]["trusted_assumptions"] != trusted


# --- the assumption relation has ONE authoritative direction -------------------------
#
# It used to have two. A unit named its premises in `[[unit]].assumptions` and an
# assumption named its units in `scope`, nothing compared them, and the two halves fed
# different machinery: `scope` reached the fingerprint and `check-assumptions`, the unit
# field reached `review-packet` and the generated views. Nine pairs diverged on main —
# ASM-0037 was scoped to `http_profile.keyid` while `http_profile.keyid_selector` declared
# it, so the selector unit's fingerprint carried no `trusted_assumptions` entry at all and
# THM-0050 read as fresh across any rewrite of the premise it stands on.
#
# ADR-MCPRE-059 §8 now names `scope` as the source. These tests hold the two properties
# that replaced the comparison: the inverse is DERIVED, and a unit-side declaration is
# UNREPRESENTABLE rather than merely policed.


def test_a_unit_trusts_exactly_what_scope_names():
    assumptions = {
        "assumption": [
            {"id": "ASM-B", "scope": ["unit://u", "boundary://boundary.clock"]},
            {"id": "ASM-A", "scope": ["unit://u"]},
            {"id": "ASM-C", "scope": ["unit://other"]},
        ]
    }
    assert unit_assumptions("u", assumptions) == ["ASM-A", "ASM-B"]
    assert unit_assumptions("other", assumptions) == ["ASM-C"]


def test_a_unit_no_scope_names_trusts_nothing():
    """Not an error. A unit whose claims rest on no registered premise is the ordinary
    case, and a withdrawn or reserved entry — ASM-0015, ASM-0016, ASM-0017, ASM-0022 —
    reaches nothing at all."""
    assert unit_assumptions("u", {"assumption": [{"id": "ASM-A", "scope": []}]}) == []


def test_a_boundary_scope_is_not_a_unit_scope():
    """`scope` carries both kinds, and only the `unit://` entries name a consumer unit —
    otherwise every claim would inherit a boundary premise no unit rests on."""
    assumptions = {"assumption": [{"id": "ASM-A", "scope": ["boundary://boundary.clock"]}]}
    assert unit_assumptions("boundary.clock", assumptions) == []


def test_a_unit_may_not_declare_its_own_assumptions():
    """The schema is what makes divergence unrepresentable. A migration gate comparing two
    sources would leave both sources in place, and the second one is the defect."""
    import _manifest
    import _record_rules

    assert "assumptions" not in _manifest._UNIT_KEYS
    try:
        _record_rules.reject_unknown("unit u", {"assumptions": ["ASM-A"]}, _manifest._UNIT_KEYS)
    except _manifest.ManifestError as refused:
        assert "assumptions" in str(refused)
    else:
        raise AssertionError("an authored unit-side declaration was accepted")


def test_a_scope_naming_no_such_unit_is_reported():
    verification = {"unit": [{"id": "u", "class": "V0", "paths": []}]}
    assumptions = {"assumption": [{"id": "ASM-X", "scope": ["unit://nope"]}]}
    defects = assumption_scope_defects(verification, assumptions)
    assert len(defects) == 1
    assert "which no [[unit]] declares" in defects[0]


def test_a_scope_naming_a_declared_unit_is_not_a_defect():
    verification = {"unit": [{"id": "u", "class": "V0", "paths": []}]}
    assumptions = {"assumption": [{"id": "ASM-X", "scope": ["unit://u"]}]}
    assert assumption_scope_defects(verification, assumptions) == []


def test_the_shipped_scopes_all_name_declared_units():
    assert assumption_scope_defects(DOC, ASSUMPTIONS) == []


def test_no_shipped_unit_declares_assumptions():
    """The migration is complete, not merely intended."""
    assert [unit["id"] for unit in DOC["unit"] if "assumptions" in unit] == []
