# SPDX-License-Identifier: Apache-2.0
"""The ADR-MCPRE-069 census's own false-green catalogue.

A census reporting `0 unclaimed` is worth exactly as much as its ability to SEE. ADR-069's
first measurement could not see doctests at all, and reported a clean sweep over a
population missing a whole control kind; that is the failure this file exists to make
impossible to repeat.

Two families of control, and they refuse different lies:

  * **positive scope** — for every ecosystem this repository actually has, a NAMED control
    that must appear in the enumeration. Not "at least one" — a specific one, by identity,
    chosen so that the assertion goes red when that ecosystem stops being discoverable
    rather than when the repository merely shrinks;
  * **sensitivity** — removing a known claimed control's registration must make the census
    report it as unclaimed, and removing the control from the tree must make its selector
    stale. A census that answered the same whatever the registry said would be measuring
    nothing, and would be green on the day the registry was emptied.

Run: python3 tools/verification/test_controls.py
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import _controls_cases_join as join  # noqa: E402
import _controls_cases_ratified as ratified  # noqa: E402
import _controls_cases_register as register  # noqa: E402
import _controls_cases_repository as repository  # noqa: E402
import _controls_cases_scope as scope  # noqa: E402

#: The case modules, each holding the `test_*` functions of one family of control.
CASE_MODULES = (scope, join, register, ratified, repository)


def test_every_supported_ecosystem_has_a_discovered_control():
    """Each named control is found, so no discovery path has gone dark.

    The control lives in this file because `scope.SCOPE` names it as the discovered pytest
    control of the repository's own tooling: the census must see the file that runs it.
    """
    scope.every_supported_ecosystem_has_a_discovered_control()


def _cases() -> dict:
    """Every `test_*` callable of this file and of the case modules, by name."""
    cases = {name: fn for name, fn in globals().items() if name.startswith("test_")}
    for module in CASE_MODULES:
        cases.update({name: fn for name, fn in vars(module).items() if name.startswith("test_")})
    return cases


def run() -> int:
    failures = 0
    for name, fn in sorted(_cases().items()):
        if not callable(fn):
            continue
        try:
            fn()
        except AssertionError as failure:
            failures += 1
            print(f"FAIL {name}: {failure}")
        else:
            print(f"ok   {name}")
    print(f"control census self-test: {'PASS' if not failures else f'FAIL ({failures})'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
