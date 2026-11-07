# SPDX-License-Identifier: Apache-2.0
"""The gate's selftest: each undone claim trips its clause, and the tree as it stands is clean."""

from __future__ import annotations

from _refusal_provenance.check import check
from _refusal_provenance.config import CORE_AUDIT, RECORD, REFUSAL, REPO, SERVING, TRANSPORT
from _refusal_provenance.selftest_cases import Scenario, scenarios
from _refusal_provenance.sources import read_unit


def _base() -> dict[str, str]:
    """The live texts a fixture overrides part of. The serving path and the record are
    subtrees; a fixture that replaces one supplies its text as one override, which
    `read_unit` honours ahead of the walk."""
    base = {r: (REPO / r).read_text() for r in REFUSAL + [CORE_AUDIT, TRANSPORT]}
    base[RECORD] = read_unit(RECORD, None)
    base[SERVING] = read_unit(SERVING, None)
    return base


def _run(scenario: Scenario, base: dict[str, str]) -> bool:
    found = check({**base, **scenario.files})
    got = len(found)
    marker = scenario.marker
    ok = got >= scenario.expected and (marker is None or any(marker in p for p in found))
    print(f"  {'ok ' if ok else 'FAIL'} {scenario.name}: {got} problem(s), expected >= {scenario.expected}")
    return ok


def _tree_is_clean() -> bool:
    """And the tree as it stands must be clean, or the pills prove nothing."""
    live = check()
    if live:
        print(f"  FAIL the working tree itself: {live}")
        return False
    print("  ok  the working tree is clean")
    return True


def selftest() -> int:
    cases = scenarios()
    base = _base()
    results = [_run(case, base) for case in cases]
    results.append(_tree_is_clean())
    failed = not all(results)
    print(f"\nrefusal-provenance selftest: {'FAIL' if failed else 'PASS'} — {len(cases) + 1} case(s)")
    return 1 if failed else 0
