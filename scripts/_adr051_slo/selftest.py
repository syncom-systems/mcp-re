# SPDX-License-Identifier: Apache-2.0
"""The comparability rules, exercised.

They decide almost nothing on a developer's own box — the default class IS the anchor's
class there — so without this they would be established only by a run on the one machine
where they never fire. The anchor and the class names come from the committed
declaration, so a class renamed in one place and not the other fails here.
"""

from __future__ import annotations

from _adr051_slo.anchor import resolve_anchor, unanchored
from _adr051_slo.config import NOT_COMPARABLE, REPO_ROOT
from slo_evidence_identity import hardware_classes


def _synth(hw, dropped=0):
    results = {
        "throughput_rps": 15000.0,
        "failures": dropped,
        "added_latency_us": {"p50": 8000, "p99": 16000, "p999": 19000},
    }
    report = {"results": results}
    if hw is not None:
        report["config"] = {"hardware_class": hw}
    return report


def _first_classes():
    """The first anchored and the first unanchored class the declaration names."""
    declared = hardware_classes().items()
    anchored = next((n for n, e in declared if e["regression_anchor"]), None)
    unanchored_name = next((n for n, e in declared if not e["regression_anchor"]), None)
    return anchored, unanchored_name


def _cases(anchored, unanchored_name):
    anchor_file = str(REPO_ROOT / hardware_classes()[anchored]["regression_anchor"])
    return [
        ("an anchored class resolves its own anchor",
         _synth(anchored), None, lambda p, r: p is not None and r is None),
        ("an unanchored class is NOT COMPARABLE, not a regression",
         _synth(unanchored_name), None,
         lambda p, r: p is None and "no committed regression anchor" in r),
        ("an undeclared class is refused rather than adjudicated",
         _synth("some-box-nobody-declared"), None, lambda p, r: p is None and "not declared" in r),
        ("a report with no hardware_class at all is refused",
         _synth(None), None, lambda p, r: p is None and "no config.hardware_class" in r),
        ("an explicit --baseline may not launder a cross-class comparison",
         _synth(unanchored_name), anchor_file, lambda p, r: p is None and "across classes" in r),
    ]


def _run_case(label, report, explicit, expected):
    path, reason = resolve_anchor(report, explicit)
    held = expected(path, reason)
    print(f"  {'ok  ' if held else 'FAIL'}  {label}")
    if not held:
        print(f"        got path={path}, reason={reason}")
    return held


def _unanchored_runs_hold(unanchored_name):
    """An UNANCHORED run is not a pass, and the hardware-independent half still bites."""
    held = True
    if unanchored(_synth(unanchored_name), "test") != NOT_COMPARABLE:
        print("  FAIL  a clean unanchored run did not report NOT COMPARABLE")
        held = False
    if unanchored(_synth(unanchored_name, dropped=7), "test") != 1:
        print("  FAIL  an unanchored run that dropped requests was not a failure")
        held = False
    return held


def selftest():
    anchored, unanchored_name = _first_classes()
    if anchored is None or unanchored_name is None:
        print("SELFTEST FAILED: the declaration needs an anchored and an unanchored class "
              f"to exercise both paths (anchored={anchored}, unanchored={unanchored_name})")
        return 1
    held = [_run_case(*case) for case in _cases(anchored, unanchored_name)]
    unanchored_held = _unanchored_runs_hold(unanchored_name)
    ok = all(held) and unanchored_held
    print("adr051_slo_gate selftest:", "OK" if ok else "FAILED")
    return 0 if ok else 1
