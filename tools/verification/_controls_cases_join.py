# SPDX-License-Identifier: Apache-2.0
"""Join correctness and sensitivity: the census must answer differently when its inputs change."""

from __future__ import annotations

import _census
from _controls_cases_support import (
    CONTROLS,
    REPORT,
    census_with,
    first_claim,
    not_evidence_row,
)


def test_no_registered_selector_names_a_control_that_does_not_exist():
    """A `tested_symbols` entry resolving to nothing is a stale identity.

    It is also the census's sharpest self-check: the lane selects with `--exact`, so a
    selector naming nothing would fail the lane — and an enumerator that had LOST a control
    kind would report every selector of that kind as stale. Zero is therefore evidence in
    both directions, which is why it is asserted rather than reported.
    """
    assert not REPORT.stale, REPORT.stale[:10]


def test_a_parametrised_family_is_one_control_claimed_by_its_cases():
    """pytest's `[case]` ids and vitest's `%s` titles resolve back to the source control."""
    pytest_family = (
        "sdk/python",
        "pytest#tests/test_nonce_floor.py::test_a_sub_floor_override_is_refused_at_sign_time",
    )
    claims = [
        claim
        for claim in REPORT.claims
        if (claim.control.project, claim.control.identity) == pytest_family
    ]
    assert len(claims) >= 2, "the four parametrised cases should all resolve to one control"
    assert all(claim.selector.endswith("]") for claim in claims), [c.selector for c in claims]


def test_a_control_is_claimed_by_selection_and_never_by_path_proximity():
    """A unit's `paths` do not claim the controls inside them.

    The worked instance is ADR-069 §3: `continuation_store/mod.rs` is in
    `proxy.continuation_correlation_store`'s paths, two of its controls are registered and
    the rest are not. If proximity claimed, the unclaimed ones would vanish — and the
    defect ADR-069 exists to measure would be unmeasurable.
    """
    claimed = REPORT.claimed
    in_file = [
        control
        for control in CONTROLS
        if control.carrier == "mcp-re-proxy/src/continuation_store/mod.rs"
    ]
    assert in_file, "the worked instance's carrier moved; retarget this control"
    assert any((c.project, c.identity) in claimed for c in in_file)
    assert any((c.project, c.identity) not in claimed for c in in_file)


def test_removing_a_registration_makes_its_control_unclaimed():
    """Delete one symbol from the registry and the census must report it.

    Performed against a COPY of the loaded registry rather than the file, so the control
    proves the join is sensitive without a test that edits committed policy.
    """
    claim = first_claim()
    perturbed = census_with([], claims=[c for c in REPORT.claims if c is not claim])
    key = (claim.control.project, claim.control.identity)
    assert key in REPORT.claimed
    assert key not in perturbed.claimed
    assert key in {(c.project, c.identity) for c in perturbed.unclaimed}


def test_a_disposition_removes_a_control_from_the_residue_and_nothing_else_does():
    """The residue is unclaimed MINUS dispositioned, and a row moves exactly one control."""
    unclaimed = REPORT.unclaimed
    assert unclaimed, "nothing unclaimed; retarget this control"
    target = unclaimed[0]
    perturbed = census_with([not_evidence_row("ND-TEST", target.project, target.identity)])
    assert len(perturbed.residue) == len(unclaimed) - 1
    assert (target.project, target.identity) not in {
        (c.project, c.identity) for c in perturbed.residue
    }


def test_a_disposition_for_a_claimed_control_is_an_orphan():
    """ADR-069 D4: a registered control leaves the census, so a row about one is refused."""
    claimed = first_claim().control
    perturbed = census_with([not_evidence_row("ND-TEST", claimed.project, claimed.identity)])
    assert [r.id for r in perturbed.orphan_dispositions] == ["ND-TEST"]


def test_a_disposition_for_a_control_that_vanished_is_an_orphan():
    """A control deleted from the tree leaves its row describing nothing."""
    row = not_evidence_row(
        "ND-GONE", "mcp-re-proxy", "src/lib.rs#a_module_that_does_not_exist::tests::gone"
    )
    assert [r.id for r in census_with([row]).orphan_dispositions] == ["ND-GONE"]


def test_a_selector_naming_a_deleted_control_is_reported_stale():
    """Remove a control from the enumeration and its registration must go stale."""
    claim = first_claim()
    thinner = [c for c in CONTROLS if c is not claim.control]
    _, stale = _census.join(thinner)
    assert claim.selector in {selector for _, _, selector in stale}
