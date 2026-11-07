# SPDX-License-Identifier: Apache-2.0
"""What every census case module reads: the live enumeration, its join, and a doctored census.

The enumeration and the join are computed once, at import, because every case asks a
question of the same tree and the same registry.
"""

from __future__ import annotations

import _census
import _controls
from _load_tool import load_tool

CONTROLS = _controls.all_controls()
INDEX = {(control.project, control.identity): control for control in CONTROLS}
REPORT = _census.census(CONTROLS)


def load_census_tool():
    """The `control-census` executable as a module — it has no `.py` suffix."""
    return load_tool("control-census", "control_census")


def first_claim():
    """The first claim on a Rust test, the control the sensitivity cases perturb."""
    for claim in REPORT.claims:
        if claim.control.kind == "rust-test":
            return claim
    raise AssertionError("no rust-test claim to perturb")


def not_evidence_row(row_id: str, project: str, control: str) -> _census.Disposition:
    """A `not-evidence` disposition about `control`, for a doctored census."""
    return _census.Disposition(
        id=row_id,
        project=project,
        control=control,
        decision="not-evidence",
        reason_family="ND-TEST",
        recorded="2026-09-19",
        proposition=None,
    )


def census_with(dispositions, claims=None) -> _census.Census:
    """The live enumeration joined to `claims` (the live ones by default) and `dispositions`."""
    return _census.Census(
        controls=CONTROLS,
        claims=REPORT.claims if claims is None else claims,
        stale=[],
        dispositions=dispositions,
    )
