# SPDX-License-Identifier: Apache-2.0
"""The human-readable report of one verdict."""

from __future__ import annotations

from dataclasses import dataclass, field

from _merge_readiness.candidate import VERIFICATION_TOML


@dataclass
class Outcome:
    """Everything the report states about one candidate."""

    sha: str
    state: str
    authority: str
    rows: list[tuple]
    units: set[str]
    declared: int
    deferred: list[str] = field(default_factory=list)


def _row_line(row: tuple) -> str:
    lane, check, mark, why = row
    # Under the ruleset authority the "lane" IS the check, so printing both would be
    # the same string twice.
    label = check if lane == check else f"{lane:<16} {check}"
    return f"  {mark:<14} {label}  [{why}]"


def report(outcome: Outcome) -> None:
    sha = outcome.sha
    print(f"candidate      {sha}")
    print(f"authority      {outcome.authority}")
    # Both numbers, and the sha they came from: a reader can see that the estate the
    # required set was derived from is the candidate's own, rather than trusting it.
    print(f"registry       {VERIFICATION_TOML}@{sha[:12]} — {outcome.declared} declared unit(s)")
    print(f"affected units {len(outcome.units)}")
    for row in outcome.rows:
        print(_row_line(row))
    if outcome.deferred:
        print(f"deferred       {', '.join(outcome.deferred)} — no pre-merge job runs these lanes; the "
              f"complete run (schedule or dispatch) remeasures them, and until then the "
              f"evidence is stale, not verified")
    print(f"MERGE-READINESS: {outcome.state}")
