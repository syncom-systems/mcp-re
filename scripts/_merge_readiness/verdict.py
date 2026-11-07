# SPDX-License-Identifier: Apache-2.0
"""The verdict: one required check against the four conditions, and the answer over a set."""

from __future__ import annotations

from typing import NamedTuple

#: The only three answers. A caller that wants to know whether to merge reads exactly one
#: of these; there is deliberately no fourth "green except…" state to argue with.
READY, NOT_READY, FAILED = "READY", "NOT_READY", "FAILED"

#: Conclusions that are a verdict about the code rather than an incomplete measurement.
#: `cancelled` is NOT here: a cancelled run measured nothing, so it is an absence.
FAILING_CONCLUSIONS = {"failure", "timed_out", "action_required", "startup_failure"}


def classify(check: dict | None, sha: str) -> tuple[bool, str]:
    """`(satisfied, why)` for one required check, against all four conditions."""
    if check is None:
        return False, "missing — no such check at this SHA"
    if check.get("head_sha") != sha:
        return False, f"measured at {str(check.get('head_sha'))[:12]}, not the candidate"
    status = check.get("status") or ""
    if status != "completed":
        return False, f"status {status or '(empty)'}"
    conclusion = check.get("conclusion") or ""
    if conclusion == "success":
        return True, "completed/success"
    return False, f"conclusion {conclusion or '(empty)'}"


def skipped_by_itself(check: dict | None, sha: str) -> bool:
    """Whether a check is completed/skipped at this SHA: the job chose not to measure."""
    return (
        bool(check)
        and check.get("head_sha") == sha
        and check.get("status") == "completed"
        and check.get("conclusion") == "skipped"
    )


class _Evidence(NamedTuple):
    """What the lanes are judged against: the runs, the candidate and the shared jobs."""

    runs: dict[str, dict]
    sha: str
    shared: set[str]

    def failed(self, name: str) -> bool:
        return (self.runs.get(name) or {}).get("conclusion") in FAILING_CONCLUSIONS


def _why_unsatisfied(lane: str, names: list[str], verdicts: list[tuple], evidence: _Evidence) -> str:
    """The reason a lane no job satisfied reads as it does."""
    red_shared = [n for n in names if n in evidence.shared and evidence.failed(n)]
    if red_shared:
        return (
            f"{red_shared[0]} failed, but it runs several lanes — its verdict is not "
            f"attributable to '{lane}'"
        )
    why = verdicts[0][2]
    if len(verdicts) > 1:
        return f"{why}; none of {len(verdicts)} jobs satisfied it"
    return why


def _lane_row(lane: str, names: list[str], evidence: _Evidence) -> tuple[str, str, str, str]:
    """`(lane, check, mark, why)` for one required lane."""
    verdicts = [(name, *classify(evidence.runs.get(name), evidence.sha)) for name in names]
    winner = next((v for v in verdicts if v[1]), None)
    if winner is not None:
        return lane, winner[0], "OK", winner[2]
    attributable = [n for n in names if n not in evidence.shared and evidence.failed(n)]
    if attributable:
        return lane, attributable[0], "FAILED", "this lane's own job failed"
    return lane, verdicts[0][0], "NOT SATISFIED", _why_unsatisfied(lane, names, verdicts, evidence)


def decide(
    required: dict[str, list[str]],
    runs: dict[str, dict],
    sha: str,
    shared: set[str] | None = None,
) -> tuple[str, list[tuple]]:
    """The answer, plus one row per required lane for the human-readable table.

    A lane is satisfied when ANY job that runs it met all four conditions — including the
    umbrella, whose SUCCESS does cover every lane it contains.

    It is `FAILED` only when a check whose verdict is that lane's OWN establishes failure.
    `shared` names the jobs that run several lanes; their failure is not attributable to
    any one of them, so it refuses as NOT_READY with the reason saying which job went red.
    Inventing a per-lane verdict from a shared job's failure would send someone to fix a
    lane that never ran badly.
    """
    evidence = _Evidence(runs, sha, shared or set())
    rows = [_lane_row(lane, names, evidence) for lane, names in sorted(required.items())]
    marks = {row[2] for row in rows}
    if "FAILED" in marks:
        return FAILED, rows
    return (READY if marks <= {"OK"} else NOT_READY), rows
