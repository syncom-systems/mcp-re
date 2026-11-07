# SPDX-License-Identifier: Apache-2.0
"""Resolving the anchor a report may be compared with, and the verdict for one it has none for."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from _adr051_slo.config import NOT_COMPARABLE, REPO_ROOT
from slo_evidence_identity import hardware_classes


def load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        print(f"adr051-slo-gate: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)


def _declared_anchor(report_hw):
    """`(anchor path, None)` for the anchor the declaration gives `report_hw`, else
    `(None, reason)`."""
    entry = hardware_classes().get(report_hw)
    if entry is None:
        return None, (
            f"hardware_class {report_hw!r} is not declared in "
            f"config/performance-surface.toml. Declare the class — with its own anchor, "
            f"or with none — before a number measured on it is adjudicated."
        )
    anchor = entry["regression_anchor"]
    if not anchor:
        return None, (
            f"hardware_class {report_hw!r} has no committed regression anchor. This run "
            f"is a measurement of a context nothing has been recorded for yet, so there "
            f"is nothing to compare it against — declare an anchor for this class from a "
            f"deliberate quiet-box run before expecting a regression verdict."
        )
    return REPO_ROOT / anchor, None


def _explicit_anchor(report_hw, explicit):
    baseline = load_json(explicit)
    anchor_hw = baseline.get("anchor", {}).get("config", {}).get("hardware_class")
    if anchor_hw != report_hw:
        return None, (
            f"the report was measured on hardware_class {report_hw!r} and {explicit} is an "
            f"anchor recorded on {anchor_hw!r}. A comparison across classes is not a "
            f"stricter or a looser gate — it is a gate about a different question."
        )
    return Path(explicit), None


def resolve_anchor(report, explicit):
    """`(baseline path, None)` when a comparison is legitimate, `(None, reason)` when not.

    The report's own `config.hardware_class` picks the anchor. An explicit `--baseline` is
    still checked against it: naming a file does not make the run a measurement of that
    file's class, and the whole defect this replaces was a comparison nobody had to state.
    """
    report_hw = report.get("config", {}).get("hardware_class")
    if report_hw is None:
        return None, (
            "the report declares no config.hardware_class, so there is no class to resolve "
            "an anchor for. Re-run through scripts/local_slo_lane.sh, which always sets one."
        )
    if explicit is None:
        return _declared_anchor(report_hw)
    return _explicit_anchor(report_hw, explicit)


def unanchored(report, reason):
    """The hardware-independent half, for a report this gate has no anchor for.

    Not a pass and not a regression. The correctness check below is hardware-independent —
    a run that dropped requests is never acceptable on any class — so the run is not left
    having established nothing, and the verdict says exactly which of the two it is.
    """
    print("=== ADR-051 §7 local-regression SLO gate ===")
    print(f"NOT COMPARABLE: {reason}")
    dropped = report.get("results", {}).get("failures", 0)
    if dropped:
        print(
            f"\nRESULT: FAIL — {dropped} request failure(s) in the run. This check is "
            f"hardware-independent and bites on every class.",
            file=sys.stderr,
        )
        return 1
    print("  [PASS] request failures                    0  (hardware-independent)")
    print(
        "\nRESULT: UNANCHORED — measured, correctness clean, regression band not "
        "established for this class.",
        file=sys.stderr,
    )
    return NOT_COMPARABLE
