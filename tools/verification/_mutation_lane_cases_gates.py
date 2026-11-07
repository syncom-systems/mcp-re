# SPDX-License-Identifier: Apache-2.0
"""Gate controls: a control that is a script rather than a test symbol.

Cases for `test_mutation_lane.py`, which runs them.
"""

from __future__ import annotations

import inspect
import subprocess
import sys
import tempfile
from pathlib import Path

from _mutation_lane_support import UNITS, expect_manifest_error, lane, make_probe


#
# ADR-MCPRE-068 Phase 1. The lane gained a second kind of control, so it gained the same
# catalogue of ways to report a green it did not measure — and one that is new: a gate is
# started by the lane rather than compiled into a battery, so "it did not start" and "it
# ran and held" are two facts a naive runner would collapse into one.


def test_expecting_a_gate_the_unit_does_not_declare_is_refused():
    """The same rule as a test symbol, and for the same reason: a gate outside the declared
    battery is not evidence for the theorem however red it goes."""
    expect_manifest_error(
        lambda: lane.declared_battery(
            UNITS, make_probe(expect_red=["gate#scripts/module_size_gate.py"]), "p"
        ),
        "a gate the unit does not declare must be refused",
    )


def test_a_declared_gate_control_resolves_as_a_battery_member():
    probe = make_probe(
        unit="proxy.dispatch_commitment",
        expect_red=["gate#scripts/authorization_provenance_gate.py"],
    )
    _package, _grouped, gates, _eco = lane.declared_battery(UNITS, probe, "p")
    assert "scripts/authorization_provenance_gate.py" in gates, gates


def test_a_gate_that_cannot_start_is_ABSENT_rather_than_RED():
    """The false RED this kind of control makes possible, which is the sharper one.

    A missing script is not a refusal. `python3 nothing.py` exits non-zero, so the obvious
    runner records `FAILED` — and a probe whose weakening DELETED or renamed the gate would
    then be satisfied by the control's disappearance. That is the mirror of the false green
    the adjudicator was already built to refuse: absence must never be a verdict, in either
    direction. MEASURED 2026-09-18 — the first version of this runner did exactly that, and
    this test is why it does not.
    """
    results = lane.run_gates(lane.REPO_ROOT, ["scripts/there_is_no_such_gate.py"])
    assert results == {}, results
    probe = make_probe(expect_red=["gate#scripts/there_is_no_such_gate.py"])
    missing, red = lane.adjudicate(probe, results)
    assert missing == ["gate#scripts/there_is_no_such_gate.py"], missing
    assert red == [], red


def test_a_gate_that_CRASHED_is_absent_rather_than_red():
    """A non-zero exit is a refusal only when the gate reached a verdict.

    A weakening that breaks the gate's own parse exits non-zero exactly as a real finding
    does, and reading that as red would let a probe be satisfied by breaking the control
    instead of the check. The discriminator is the traceback, because that is the one thing
    a gate that reached a verdict never prints.
    """
    with tempfile.TemporaryDirectory() as raw:
        tree = Path(raw)
        (tree / "scripts").mkdir()
        (tree / "scripts/crasher.py").write_text("raise RuntimeError('broken gate')\n")
        assert lane.run_gates(tree, ["scripts/crasher.py"]) == {}
        # And a gate that refuses in the ordinary way IS red, so the rule above is a
        # discriminator rather than a blanket excuse.
        (tree / "scripts/refuser.py").write_text(
            "import sys\nprint('a finding')\nsys.exit(1)\n"
        )
        assert lane.run_gates(tree, ["scripts/refuser.py"]) == {
            "gate#scripts/refuser.py": "FAILED"
        }


def test_a_gate_reports_in_the_same_vocabulary_as_a_libtest_line():
    """The adjudicator asks one question of every control and must not learn where it came
    from, so a gate's exit status is translated at the boundary rather than special-cased
    downstream."""
    ok = lane.run_gates(lane.REPO_ROOT, ["scripts/serving_product_provenance_gate.py"])
    assert ok == {"gate#scripts/serving_product_provenance_gate.py": "ok"}, ok
    # And the red half, measured rather than asserted: the gate's own selftest exits 0, so
    # a non-zero exit has to come from a real refusal. `--selftest` is used here only to
    # confirm the gate is the kind of thing that can refuse at all.
    proc = subprocess.run(
        [sys.executable, "scripts/serving_product_provenance_gate.py", "--selftest"],
        cwd=lane.REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr


def test_a_declared_gate_control_must_exist_in_the_tree():
    """A control the lane cannot run is not evidence, however it is described."""
    from _manifest import _validate_gate_controls

    expect_manifest_error(
        lambda: _validate_gate_controls(
            "u", {"gate_controls": ["scripts/there_is_no_such_gate.py"]}
        ),
        "a gate control that is not a file must be refused",
    )
    # The registered ones pass, so the refusal above is about the missing file and not
    # about the check being unsatisfiable.
    _validate_gate_controls("u", UNITS["proxy.dispatch_commitment"])


def test_gate_controls_enter_the_unit_fingerprint():
    """Softening a rule is a reduction in evidence, so it must invalidate the attestation.

    The scripts cannot go in `paths` — a `.py` entry collapses a Rust unit's ecosystem —
    so the component is what carries them, and a unit that declares none must not gain an
    empty key: that would move all 156 fingerprints to record an absence.
    """
    import _fingerprint

    unit = UNITS["proxy.dispatch_commitment"]
    assert unit.get("gate_controls"), "the fixture unit must declare gate controls"
    source = inspect.getsource(_fingerprint)
    assert 'if unit.get("gate_controls"):' in source
    assert 'components["gate_controls"] = _digest_paths' in source
