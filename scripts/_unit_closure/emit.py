"""`--emit-register`: print a register for the current tree."""

from __future__ import annotations

import subprocess

from _unit_closure.config import REPO, exclusions
from _unit_closure.rules import flag


def _entry_lines(rel: str, why: str, prior: dict, sha: str) -> list[str]:
    lines = [
        "\n[[exclusion]]",
        f'path = "{rel}"',
        f'rule = "{why.split(":", 1)[0]}"',
        f'baseline_sha = "{prior.get("baseline_sha") or sha}"',
        f'status = "{prior.get("status", "unreviewed")}"',
    ]
    if prior.get("reason"):
        lines.append(f'reason = "{prior["reason"]}"')
    if prior.get("review_ref"):
        lines.append(f'review_ref = "{prior["review_ref"]}"')
    return lines


def emit_register() -> int:
    """Print a register for the current tree, carrying existing dispositions forward."""
    from _manifest import load_verification  # noqa: PLC0415

    sha = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout.strip()
    existing = exclusions().current()
    findings, _ = flag(REPO, load_verification()["unit"])
    print(
        f"# Unit-closure exclusions — files the module tree reaches from a measured unit\n"
        f"# that no unit's `paths` answer for. Emitted at {sha}: {len(findings)} entries.\n"
        f"#\n"
        f"# A debt register, not an exception mechanism. It may only shrink; see\n"
        f"# scripts/unit_closure_gate.py."
    )
    for rel, why in sorted(findings.items()):
        for line in _entry_lines(rel, why, existing.get(rel, {}), sha):
            print(line)
    return 0
