# SPDX-License-Identifier: Apache-2.0
"""`boundary.clock` models the clock authority of the source tree, not a snapshot of the manifest."""

from __future__ import annotations

from pathlib import Path

from _boundary_crossings import boundary_class_violations
from _rust_source import production_view
from _trust_boundaries import load_trust_boundaries
from _measured_inputs_support import (
    ASSUMPTIONS,
    BOUNDARIES_REAL,
    HERE,
    REPO,
    UNITS,
    scoped,
)


# --- boundary.clock models the authority, not a snapshot of the manifest -------
#
# The synthetic cases above prove the CAP is enforced. These prove the DECLARATION is
# true of the source tree — the half that was wrong for as long as the cap was inert:
# boundary.clock named mcp-re-core/src/time.rs, which held no clock authority, and named
# none of the sixteen production sites that do. Fixing the manifest alone would leave the
# relationship untested and free to drift back on the next file that reads a clock.

REPO = HERE.parent.parent
BOUNDARIES_REAL = load_trust_boundaries()

# Acquisition is `SystemTime::now()` — the call that asks the OS what time it is.
# UNIX_EPOCH alone is NOT the signal: it also appears where an already-supplied
# SystemTime is converted (mcp-re-proxy/src/ocsp.rs), which is transformation.
ACQUIRES = "SystemTime::now()"


def _clock_boundary() -> dict:
    for boundary in BOUNDARIES_REAL["boundary"]:
        if boundary["id"] == "boundary.clock":
            return boundary
    raise AssertionError("boundary.clock is not declared")


def _production_source(path) -> str:
    """A file's production source: `_rust_source`'s view, with every test region removed.

    A test module reading the clock is not a production clock authority, and counting one
    would make the boundary grow on test code.
    """
    return production_view(Path(path)).text()


def _acquisition_sites() -> set[str]:
    found = set()
    for path in sorted(REPO.glob("mcp-re-*/src/**/*.rs")):
        if ACQUIRES in _production_source(path):
            found.add(str(path.relative_to(REPO)))
    return found


def test_the_clock_boundary_names_every_acquisition_site():
    """Every production `SystemTime::now()` site is declared, and nothing else is.

    This is the test that makes the boundary model the AUTHORITY rather than the three
    grep hits that happened to be obvious on the day it was written. A new file that
    reads the OS clock fails here until it is declared."""
    declared = set(_clock_boundary()["paths"])
    actual = _acquisition_sites()
    assert not (actual - declared), (
        f"undeclared wall-clock acquisition site(s): {sorted(actual - declared)}"
    )
    assert not (declared - actual), (
        f"declared but acquires no wall-clock time: {sorted(declared - actual)}"
    )


def test_timestamp_transformation_is_outside_the_clock_boundary():
    """The original defect, pinned. `mcp-re-core/src/time/` converts RFC 3339 text to
    Unix seconds and holds no clock authority — ADR-MCPS-006 pushes timestamps to
    callers, and ADR-MCPS-011/012 purity means the crate cannot read a clock at all.

    Read over the whole subtree rather than one file: MCPRE-176 split the formatting
    inverse into `format.rs`, and a control that kept naming `time.rs` would have gone on
    passing while measuring a file that no longer exists."""
    members = sorted((REPO / "mcp-re-core" / "src" / "time").rglob("*.rs"))
    assert members, "the time module has no source to measure"
    for path in members:
        rel = str(path.relative_to(REPO))
        assert rel not in _clock_boundary()["paths"]
        text = path.read_text(encoding="utf-8")
        assert ACQUIRES not in text
        assert "UNIX_EPOCH" not in text


def test_a_clock_acquisition_site_alone_is_not_a_trusted_premise():
    """This test asserted the opposite until the owner ruling of 2026-09-03, and the ruling
    is what changed, not the tree.

    `mcp-re-host/src/clock.rs` is a wall-clock ACQUISITION site and `boundary.clock`
    rightly names it. It carries no trusted seam, and a V1 unit over it consumes no
    unproved proposition FROM IT: to verify at all, the author would have to mark the
    acquisition `external_body` — at which point a seam exists and the cap fires. Until
    then the Verus lane simply fails, so there is no route to passing V1 evidence
    that this rule lets through.

    Refusing on the bare file was the source-level conflation the ruling forbids: an
    acquisition site is a place the PRODUCT reads a clock, not a place a PROOF trusts one.
    """
    unit = {
        "unit": [
            {"id": "u", "class": "V1", "paths": ["mcp-re-host/src/clock.rs"]},
        ]
    }
    # The assertion names the boundary it is about. It was `== []` until the v0.17 TCB
    # slice, which is a GLOBAL claim — that this hypothetical unit crosses nothing at all —
    # and that held only while the registry happened to declare five boundaries. Declaring
    # `boundary.unmodelled_own_behaviour` made it false for a reason with nothing to do with
    # clocks: `mcp-re-host` depends on `mcp-re-core`, so this unit's evidence cone reaches
    # the seams in `time/mod.rs`, and a proof there really would be stated over them.
    #
    # A test whose subject is one rule must not assert a property of every rule, or the next
    # correctly-declared boundary breaks it and the breakage says nothing about clocks.
    violations = boundary_class_violations(unit, BOUNDARIES_REAL, scoped())
    assert not [entry for entry in violations if "boundary.clock" in entry], violations


def test_the_preserved_unit_is_still_v1_and_assumes_nothing_about_a_clock():
    """core.time_rfc3339 keeps its class and gains no fictitious assumption. Repairing the
    boundary must not have been paid for out of the unit's evidence."""
    unit = UNITS["core.time_rfc3339"]
    assert unit["class"] == "V1"
    assert boundary_class_violations({"unit": [unit]}, BOUNDARIES_REAL, ASSUMPTIONS) == []
    for entry in ASSUMPTIONS.get("assumption", []):
        scope = [str(target) for target in entry.get("scope", [])]
        if "unit://core.time_rfc3339" in scope:
            assert "boundary://boundary.clock" not in scope, entry["id"]
