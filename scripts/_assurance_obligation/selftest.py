# SPDX-License-Identifier: Apache-2.0
"""The gate's selftest: every rule, and both of its directions."""

from __future__ import annotations

import tempfile
from pathlib import Path

import _ratchet

from _assurance_obligation.defects import defects
from _assurance_obligation.registry import SCHEMA, load_registry
from _assurance_obligation.selftest_cases import Scenario, parser_cases, ratchet_scenarios, succession_scenarios


def _report(label: str, ok: bool, got: object) -> bool:
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        got {got}")
    return ok


def _run_scenario(scenario: Scenario) -> bool:
    found = defects(scenario.measured, scenario.registry, scenario.basis)
    expect = scenario.expect
    ok = (not found) if expect is None else any(expect in entry for entry in found)
    return _report(scenario.label, ok, found)


def _parser_refuses(label: str, body: str, expect: str) -> bool:
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as handle:
        handle.write("[[obligation]]\n" + body)
        temp = Path(handle.name)
    try:
        load_registry(_ratchet.Register(temp.name, SCHEMA, temp.parent))
    except ValueError as exc:
        return _report(f"the parser refuses {label}", expect in str(exc), exc)
    finally:
        temp.unlink()
    print(f"  FAIL  the parser refuses {label}")
    return False


def selftest() -> int:
    results = [_run_scenario(s) for s in ratchet_scenarios()]
    results += [_run_scenario(s) for s in succession_scenarios()]
    results += [_parser_refuses(*case) for case in parser_cases()]
    failed = not all(results)
    print(f"\nassurance-obligation gate selftest: {'FAILED' if failed else 'passed'}")
    return 1 if failed else 0
