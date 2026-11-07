# SPDX-License-Identifier: Apache-2.0
"""`--emit-registry`: print a debt registry for the current tree."""

from __future__ import annotations

import subprocess

from _module_size.config import REPO, THRESHOLD
from _module_size.measure import production_lines, register

from _rust_source import crate_sources  # noqa: E402


def baseline_sha() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:
        return "unknown"


def _oversized_rows() -> list[tuple[str, int]]:
    rows = []
    for p in crate_sources(REPO):
        prod = production_lines(p.read_text(encoding="utf-8", errors="replace"))
        if prod > THRESHOLD:
            rows.append((str(p.relative_to(REPO)), prod))
    rows.sort(key=lambda r: (-r[1], r[0]))
    return rows


def _print_row(rel: str, prod: int, prior: dict, sha: str) -> None:
    print("\n[[debt]]")
    print(f'path = "{rel}"')
    print(f"baseline_prod_loc = {prod}")
    # A number that did not move keeps the SHA where it was established; only a
    # changed count is newly baselined.
    established = prior.get("baseline_sha") if prior.get("baseline_prod_loc") == prod else None
    print(f'baseline_sha = "{established or sha}"')
    print(f'status = "{prior.get("status", "unreviewed")}"')
    if prior.get("review_ref"):
        print(f'review_ref = "{prior["review_ref"]}"')
    # Carried forward, never invented. Re-emitting must not silently mint an upward
    # authorization for a number this tool just raised on its own; if the pair no longer
    # describes a spent transition, `check_baseline_growth` says so.
    if prior.get("growth_from_prod_loc") is not None:
        print(f'growth_from_prod_loc = {prior["growth_from_prod_loc"]}')
    if prior.get("growth_ref"):
        print(f'growth_ref = "{prior["growth_ref"]}"')


def emit_registry() -> int:
    """Print a debt registry for the current tree.

    Dispositions and their `review_ref`s are CARRIED FORWARD from the existing registry.
    Re-emitting used to stamp every entry `unreviewed`, which would silently erase every
    completed census — the same defect the disposition states exist to prevent, arriving
    through the tool that refreshes the numbers.
    """
    sha = baseline_sha()
    existing = register().current()
    rows = _oversized_rows()
    print(f"# Baselined at {sha}: {len(rows)} files over {THRESHOLD} production lines.")
    for rel, prod in rows:
        _print_row(rel, prod, existing.get(rel, {}), sha)
    return 0
