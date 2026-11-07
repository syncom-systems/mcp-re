"""Severity ranking and the evaluator tier a file needs."""
from __future__ import annotations

SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Categories whose findings are decidable from the file's own text: a declaration
# has the wrong shape, a symbol is unreferenced, a name breaks a convention. They
# need no call-graph reasoning, no exploitability judgment, no crypto argument.
# Everything NOT in this set implies a claim about behaviour, and goes senior.
MECHANICAL = {"conformance", "dead-code", "typed-surface", "documentation", "naming"}


def severity_weight(finding: dict) -> int:
    return SEV_WEIGHT.get(str(finding.get("severity", "")).lower(), 0)


def max_sev(findings: list[dict]) -> int:
    return max((severity_weight(f) for f in findings), default=0)


def by_severity(findings: list[dict]) -> list[dict]:
    """Most severe first; ties keep the order they arrived in."""
    return sorted(findings, key=lambda r: -severity_weight(r))


def eval_tier(findings: list[dict]) -> tuple[str, str]:
    """Which evaluator tier this file needs, and why.

    Tier by the blast radius of being WRONG, not by how hard the task looks. A
    cheap evaluator is admitted only where every finding is mechanical and none is
    severe — and even then it may not close one (see ACTIONABLE).
    """
    if any(str(f.get("status", "")).lower() == "needs-senior-eval" for f in findings):
        return "senior", "a cheap evaluator asked to close a finding here"
    if max_sev(findings) >= 3:
        return "senior", "carries a critical or high"
    off = sorted({str(f.get("category", "?")).lower() for f in findings} - MECHANICAL)
    if off:
        return "senior", "behavioural categories present: " + ", ".join(off[:4])
    return "cheap", "all findings mechanical, worst severity medium or below"


def gate_tier(importers: int) -> str:
    """A file nothing imports can be gated locally; a widely imported declaration
    cannot — CLAUDE.md rule 15: changed-file validation establishes LOCAL
    correctness only, and says nothing about what binds the shape you edit."""
    return "local" if importers == 0 else ("wide" if importers <= 50 else "platform")
