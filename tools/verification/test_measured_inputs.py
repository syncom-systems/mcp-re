# SPDX-License-Identifier: Apache-2.0
"""What the platform claims to have measured, and what it actually compared.

Three separate places the platform reported an established property over inputs nothing
had looked at:

  * the ReviewFingerprint recorded constant sentinels for whole components, so the
    freshness derivation compared them, found them equal, and answered FRESH over inputs it
    had never seen;
  * the fingerprint covered a unit's DECLARED paths while the Verus lane verified the whole
    crate, so source inside the proof cone could change without moving any component;
  * `verify --gate` exited 0 on INCOMPLETE, so the only gating CI step passed for a run in
    which no required lane produced formal evidence;
  * `max_class_without_assumption` was validated as a string and enforced nowhere, so a
    unit could claim V1 over a boundary capped at V0.

Run: python3 tools/verification/test_measured_inputs.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _measured_inputs_test_selection
import _measured_inputs_lean
import _measured_inputs_read_set
import _measured_inputs_absent_components
import _measured_inputs_boundary_fingerprint
import _measured_inputs_boundary_crossings
import _measured_inputs_clock_boundary
import _measured_inputs_assumption_scope
import _measured_inputs_contract_edges
import _measured_inputs_verus_lane
import _measured_inputs_gate_exit

MODULES = (
    _measured_inputs_test_selection,
    _measured_inputs_lean,
    _measured_inputs_read_set,
    _measured_inputs_absent_components,
    _measured_inputs_boundary_fingerprint,
    _measured_inputs_boundary_crossings,
    _measured_inputs_clock_boundary,
    _measured_inputs_assumption_scope,
    _measured_inputs_contract_edges,
    _measured_inputs_verus_lane,
    _measured_inputs_gate_exit,
)


def collect() -> dict:
    """Every `test_*` callable of every case module, by name."""
    return {
        name: fn
        for module in MODULES
        for name, fn in vars(module).items()
        if name.startswith("test_") and callable(fn)
    }


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(collect().items()):
        try:
            fn()
            print(f"ok   {name}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
