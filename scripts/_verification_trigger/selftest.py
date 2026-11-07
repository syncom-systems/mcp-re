# SPDX-License-Identifier: Apache-2.0
"""The selftest: each control must make the gate fail for the stated reason, and the real tree pass."""

from __future__ import annotations

from _verification_trigger.config import REPO

import _affected

from _verification_trigger.gate import all_failures, read_texts
from _verification_trigger.paths import stale_filters
from _verification_trigger.reading import starts_on
from _verification_trigger.selftest_controls import all_controls

GLOB = 'on:\n  pull_request:\n    paths:\n      - "mcp-re-proxy/src/tls_plane.rs"\n'


class Report:
    """Prints one line per case and remembers whether any failed."""

    def __init__(self) -> None:
        self.failed = False

    def case(self, label: str, ok: bool, got: object = None) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            self.failed = True
            print(f"        got {got}")


def _run_controls(report: Report, texts: dict[str, str], deferral, required: list[str]) -> None:
    for label, mutated, expected in all_controls(texts):
        failures = all_failures(mutated, deferral, required)
        report.case(label, any(expected in f for f in failures), failures)


def _run_fixed_cases(report: Report, texts: dict[str, str], deferral) -> None:
    report.case("a PR changing MODULE.bazel starts pre-merge", starts_on(texts["pre-merge.yml"], "pull_request", "MODULE.bazel"))
    report.case("a platform change is deferred by select-units", deferral(["tools/verification/verify"]) is not None)
    report.case("an ordinary source change is not deferred as a platform change", deferral(["mcp-re-core/src/lib.rs"]) is None)
    report.case("a wildcard-free filter naming a moved file is STALE",
                stale_filters(GLOB, REPO, []) == ["mcp-re-proxy/src/tls_plane.rs"])
    report.case("an absent path that IS a fingerprint input is live, not stale",
                stale_filters(GLOB, REPO, ["mcp-re-proxy/src/tls_plane.rs"]) == [])


def selftest() -> int:
    report = Report()
    texts = read_texts()
    deferral = _affected.platform_change
    # Deriving the fingerprint read set measures every unit (about a minute); the real run does
    # it, and the controls below need only the workflow files.
    required: list[str] = []
    base = all_failures(texts, deferral, required)
    report.case("the real workflows satisfy the contract", not base, base)
    _run_controls(report, texts, deferral, required)
    _run_fixed_cases(report, texts, deferral)
    if report.failed:
        print("verification-trigger gate: SELFTEST FAILED")
        return 1
    print("verification-trigger gate: selftest passed")
    return 0
