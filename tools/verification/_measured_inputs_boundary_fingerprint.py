# SPDX-License-Identifier: Apache-2.0
"""A trust boundary's cap and paths are part of the fingerprint of the units it binds, and only of those."""

from __future__ import annotations

from _measured_inputs_support import (
    BOUNDARIES_REAL,
    UNITS,
    measure,
)


# --- the boundary cap a claim's honesty rests on -------------------------------


def test_widening_a_boundarys_cap_dirties_the_units_it_binds():
    """R9-C005 / R9-C041. `trust-boundaries.toml` was a gate in NO fingerprint.

    `max_class_without_assumption` is what keeps a proof's meaning honest across a trust
    boundary — a theorem about code on this side says nothing about the other side. It
    participated in no `ReviewFingerprint`, so widening the cap relaxed the rule and
    invalidated nothing: every claim above it kept deriving FRESH while the argument
    beneath it had changed.
    """
    unit = UNITS["proxy.epoch_bound_session_store"]
    before = measure(unit, boundaries=BOUNDARIES_REAL)
    widened = {
        "boundary": [
            dict(entry, max_class_without_assumption="V3")
            for entry in BOUNDARIES_REAL.get("boundary", [])
        ]
    }
    after = measure(unit, boundaries=widened)
    assert before["fingerprint"] != after["fingerprint"]


def test_narrowing_a_boundarys_paths_dirties_the_unit_it_stops_covering():
    """The other way a cap is relaxed, and the one a cap-only digest would miss.

    `paths` decides WHICH units the cap binds. A boundary narrowed until it no longer
    covers a unit has stopped bounding that unit's class, which is the same relaxation
    reached by a different field.
    """
    unit = UNITS["proxy.epoch_bound_session_store"]
    before = measure(unit, boundaries=BOUNDARIES_REAL)
    emptied = {
        "boundary": [
            dict(entry, paths=["verification/policy/*.toml"])
            for entry in BOUNDARIES_REAL.get("boundary", [])
        ]
    }
    after = measure(unit, boundaries=emptied)
    assert before["fingerprint"] != after["fingerprint"]


def test_a_boundary_a_unit_does_not_cross_does_not_dirty_it():
    """Without this the component is "every boundary", and one edit dirties the tree.

    A fingerprint that moves for a change the unit's argument does not rest on trains
    reviewers to re-approve without reading, which is the failure a too-wide blast radius
    produces.
    """
    unit = UNITS["core.time_rfc3339"]
    crossed = measure(unit, boundaries=BOUNDARIES_REAL)[
        "components"
    ]["governing_boundaries"]
    unrelated = {
        "boundary": [
            dict(entry, beyond="something else entirely")
            if entry["id"] not in crossed
            else entry
            for entry in BOUNDARIES_REAL.get("boundary", [])
        ]
    }
    before = measure(unit, boundaries=BOUNDARIES_REAL)
    after = measure(unit, boundaries=unrelated)
    assert before["fingerprint"] == after["fingerprint"]
