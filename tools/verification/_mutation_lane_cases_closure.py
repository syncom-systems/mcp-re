# SPDX-License-Identifier: Apache-2.0
"""The lane is inside the attestation closure.

Cases for `test_mutation_lane.py`, which runs them.
"""

from __future__ import annotations

import inspect
import subprocess
import sys

from _mutation_lane_support import HERE, UNITS, lane


def test_the_unit_declares_mutation_evidence_so_attestation_depends_on_it():
    """Without the `mutation://` URI the probe suite is decoration: `attest` would issue
    `http_profile.request_floor_result` from the ordinary test evidence alone, and the CI job
    could be deleted with no unit ever deriving DIRTY."""
    from _evidence import required_lanes

    unit = UNITS["http_profile.request_floor_result"]
    assert lane.claims(unit, "mutation")
    assert "mutation" in required_lanes(unit)


def test_attest_reads_the_mutation_lane():
    """A lane `attest` does not load refuses forever — a refusal no measurement can
    satisfy, which reads as a defect in the unit rather than an absent reader."""
    text = (lane.REPO_ROOT / "tools/verification/attest").read_text()
    assert '"test", "verus", "lean", "mutation"' in text


def test_a_partial_run_writes_no_evidence_record():
    """`--probe` measures part of the battery. A record from it would let "three probes
    passed" stand in for "the suite passed"."""
    assert "if not args.probe:" in inspect.getsource(lane.main)


def test_the_probe_set_participates_in_the_units_fingerprint():
    """A closure over a suite that can silently shrink proves as little as the v3 test
    component did: deleting a probe must invalidate the standing mutation PASS."""
    from _fingerprint import Registries
    from _fingerprint import fingerprint_unit
    from _manifest import load_verification
    from _assumptions import load_assumptions
    from _toolchain_lock import load_toolchains

    doc = load_verification()
    toolchains, assumptions = load_toolchains(), load_assumptions()
    unit = UNITS["http_profile.request_floor_result"]
    registries = Registries(doc, toolchains, assumptions)
    components = fingerprint_unit(unit, registries)["components"]
    scoped = [p for p in lane.load_probes() if p["unit"] == unit["id"]]
    assert len(components["mutation_probes"]) == len(scoped)
    assert components["mutation_lane_identity"], "the lane binary must be measured"

    # And SCOPED: another unit's probes must not enter this unit's fingerprint, or every
    # unit would be dirtied by every other unit's probe edits.
    other = UNITS["proxy.epoch_bound_session_store"]
    other_probes = fingerprint_unit(other, registries)["components"]["mutation_probes"]
    assert set(other_probes).isdisjoint(components["mutation_probes"])
    assert other_probes


def test_a_selector_that_matches_nothing_is_a_FAIL():
    """`--probe M25` selects nothing, because every id is `M25-<what-it-weakens>`. That
    reported NOT_REQUIRED and exited 0, so a mistyped selector was indistinguishable from a
    tree with no probes to apply. An empty SELECTION and an empty REGISTRY are two facts."""
    proc = subprocess.run(
        [sys.executable, str(HERE / "verify-mutations"), "--probe", "M25"],
        cwd=lane.REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0, "a selector matching nothing must not exit 0"
    assert "VERDICT: FAIL" in proc.stdout, proc.stdout
    assert "selected NO registered probe" in proc.stderr, proc.stderr


def test_the_documented_matrix_count_is_checked_against_the_registry():
    """Prose is a claim. The blueprint's count drifted from 26 to 27 the first time this
    matrix was written by hand."""
    probes = lane.load_probes()
    assert lane.check_matrix_count(probes) is None
    documented = [p for p in probes if p["unit"] in lane.MATRIX_UNITS]
    assert lane.check_matrix_count(documented[:3]) is not None
    # Another unit's probes are not part of that section's count, so adding one must not
    # make the document look stale.
    assert lane.check_matrix_count(probes + [{"unit": "proxy.epoch_bound_session_store"}]) is None
