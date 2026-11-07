# SPDX-License-Identifier: Apache-2.0
"""A unit that claims no lane measures that lane's components as empty, not as a sentinel and not as another unit's evidence."""

from __future__ import annotations

from _measured_inputs_support import (
    components,
    measure,
)


def test_a_unit_without_mutation_evidence_measures_no_mutation_components():
    """Empty, and measured as empty: a unit with no probe suite must not be dirtied by
    another unit's probes, and the component must not become a sentinel.

    The subject is a STRUCTURAL unit on purpose. N1 owes a `mutation://` falsifier to
    `tested` propositions, so any `tested` unit is a fixture with an expiry date — this
    control was written over `http_profile.keyid` and went red the day that unit's probes
    were registered, asserting nothing about the emptiness it exists to measure."""
    c = components("proxy.runtime_lifecycle_sole_mutator")
    assert c["mutation_probes"] == {}
    assert c["mutation_lane_identity"] == {}


def test_the_structural_probe_set_is_measured_so_it_cannot_silently_shrink():
    """ADR-MCPRE-068 Phase 0D, and the same argument as the mutation components one line
    up: `structural://` puts the compile-refusal probes inside the attestation closure, and
    a closure over a suite that can shrink proves nothing. Each entry is digested WHOLE, so
    softening a hostile construction into one that was never illegal — or widening the
    expected error code to something any broken build produces — moves the fingerprint."""
    c = components("http_profile.verifier_result_separation")
    probes = c["structural_probes"]
    assert len(probes) >= 4, probes
    assert all(digest.startswith("sha256:") for digest in probes.values())
    assert set(c["structural_lane_identity"]) == {
        "tools/verification/verify-structural",
        # The ADJUDICATOR is part of the lane's identity, separately from the runner: it
        # decides whether a refusal is attributable to the boundary the probe attacks, and
        # a change there changes what every structural record means.
        "tools/verification/_structural.py",
        # Which units the lane covers: the scheme that claims it is the catalogue's.
        "tools/verification/_lanes.py",
    }


def test_a_unit_without_structural_evidence_measures_no_structural_components():
    """Empty, and measured as empty: a unit with no compile-refusal probes must not be
    dirtied by another unit's, and the component must not become a sentinel."""
    c = components("http_profile.keyid")
    assert c["structural_probes"] == {}
    assert c["structural_lane_identity"] == {}
    assert c["measurements"] == {}
    assert c["measured_lane_identity"] == {}


def test_a_reclassified_unit_stops_measuring_the_battery_it_no_longer_declares():
    """The transition is not only a label. `http_profile.verifier_result_separation` dropped
    its `test://` URI with its class, so its test components go empty in the same commit —
    a unit still measuring a battery no lane selects would keep deriving DIRTY on churn in
    evidence nothing reads."""
    c = components("http_profile.verifier_result_separation")
    assert c["test_selection"] == {}
    assert c["mutation_probes"] == {}


def test_a_unit_without_test_evidence_measures_no_test_components():
    """Empty, and measured as empty — a Verus-only unit must not be dirtied by test-lane
    churn, and the component must not silently become a sentinel either."""
    unit = {
        "id": "x",
        "class": "V0",
        "paths": ["mcp-re-core/src/time/mod.rs"],
        "evidence": ["verus://core/time/x"],
    }
    c = measure(unit)["components"]
    assert c["test_selection"] == {}
    assert c["test_sources"] == {}
    assert c["test_lane_identity"] == {}
