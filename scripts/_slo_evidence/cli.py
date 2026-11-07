# SPDX-License-Identifier: Apache-2.0
"""The command line: validate, emit, decide, record, report the runner class, or selftest."""

from __future__ import annotations

import argparse
import json

from _slo_evidence.check import check
from _slo_evidence.classes import runner_class
from _slo_evidence.context import context_digest, measurement_context
from _slo_evidence.selftest import selftest
from _slo_evidence.store import decide, record
from _slo_evidence.surface import performance_surface


def _parser(description: str | None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--emit", action="store_true", help="print the current identity")
    parser.add_argument("--decide", action="store_true", help="REUSE (0) or REMEASURE (10)")
    parser.add_argument("--record", nargs="+", metavar="REPORT", help="attest these reports at the current identity")
    parser.add_argument("--verdict", default="PASS", choices=("PASS", "FAIL", "INCONCLUSIVE"))
    parser.add_argument("--max-age-days", type=int, help="override the declared reuse window")
    parser.add_argument("--runner-class", action="store_true",
                        help="print the hardware_class the controlled measurement host measures as")
    parser.add_argument("--selftest", action="store_true")
    return parser


def _emit() -> int:
    surface, _ = performance_surface()
    context = measurement_context()
    print(json.dumps({"performance_surface": surface,
                      "measurement_context": context,
                      "measurement_context_digest": context_digest(context)}, indent=1, sort_keys=True))
    return 0


def _decide(max_age_days: int | None) -> int:
    verdict, reason, code = decide(max_age_days)
    print(f"SLO EVIDENCE: {verdict} — {reason}")
    return code


def _print_runner_class() -> int:
    print(runner_class())
    return 0


def run(description: str | None = None) -> int:
    args = _parser(description).parse_args()
    if args.selftest:
        return selftest()
    if args.runner_class:
        return _print_runner_class()
    if args.emit:
        return _emit()
    if args.record:
        return record(args.record, args.verdict)
    if args.decide:
        return _decide(args.max_age_days)
    return check()
