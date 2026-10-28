#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pre-merge budget — a required check passes only when every shard it stands for passed,
and the run reached it inside the pre-merge time budget.

WHAT THIS PROVES, exactly: for the one required check whose job runs it, every job that
check `needs:` concluded `success`, and the workflow run had been going for no more than
`--budget-seconds` when this check ran — measured from the run attempt's own start time as
the GitHub API reports it. It prints every job of the attempt with its queue and run time,
so a run states its own timing rather than leaving it to be inferred, and a run past
`--target-seconds` but inside the budget passes with a warning annotation, so drift shows
on the pull request before it fails one.

WHY. The required checks are names in the branch ruleset, and the pre-merge work behind
each one runs as several jobs in parallel so that the whole workflow fits its budget. A job
that `needs:` a failed job is SKIPPED, and GitHub reads a skipped required check as
passing. So the job carrying the required name runs `if: always()` and decides itself:
anything but `success` from any shard — failure, cancellation, a skip, a timeout — fails
the required check. Moving work into a shard therefore never moves it off the required
path.

The budget is measured, not configured. `timeout-minutes` bounds each job's own run; it
says nothing about the time a pull request waits for its checks, which is what the budget
is about. A measurement that cannot be made fails the check: a budget nobody measured is
not a budget.

WHAT IT DOES NOT PROVE: anything about the work inside the shards, which each shard's own
steps establish.

Run:  NEEDS_JSON='${{ toJSON(needs) }}' python3 scripts/pre_merge_budget.py --check NAME
      python3 scripts/pre_merge_budget.py --selftest
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import urllib.request

#: The pre-merge budget, end to end, in seconds: a run past it fails the required check.
BUDGET_SECONDS = 360
#: The pre-merge target: a run past it, inside the budget, passes with a warning.
TARGET_SECONDS = 240


def _when(stamp: str | None) -> datetime.datetime | None:
    if not stamp:
        return None
    return datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def shard_problems(needs: dict) -> list[str]:
    """One problem per shard that did not succeed; one if there are no shards at all."""
    if not needs:
        return ["the check names no shard: a required check standing for nothing passed nothing"]
    return [
        f"shard {name!r} concluded {str(entry.get('result'))!r}, not 'success'"
        for name, entry in sorted(needs.items())
        if entry.get("result") != "success"
    ]


def budget_problem(started: str | None, now: datetime.datetime, budget: int) -> str | None:
    """Why the run is over budget, or could not be measured; None when it is inside."""
    begun = _when(started)
    if begun is None:
        return "the run's start time could not be read, so the budget was not measured"
    elapsed = (now - begun).total_seconds()
    if elapsed > budget:
        return f"the run took {elapsed:.0f}s to reach this check; the pre-merge budget is {budget}s"
    return None


def target_warning(started: str | None, now: datetime.datetime, target: int) -> str | None:
    """Why the run missed the target; None when it is inside it or was not measured."""
    begun = _when(started)
    if begun is None:
        return None
    elapsed = (now - begun).total_seconds()
    if elapsed > target:
        return f"the run took {elapsed:.0f}s to reach this check; the pre-merge target is {target}s"
    return None


def job_lines(jobs: list[dict]) -> list[str]:
    """`queued  ran  name` per job of the attempt, slowest first, for the run's record."""
    rows = []
    for job in jobs:
        created, started, completed = (_when(job.get(k)) for k in ("created_at", "started_at", "completed_at"))
        queued = (started - created).total_seconds() if created and started else None
        ran = (completed - started).total_seconds() if started and completed else None
        rows.append((ran if ran is not None else -1.0, queued, job.get("name", "?"), job.get("conclusion")))
    out = []
    for ran, queued, name, conclusion in sorted(rows, key=lambda r: r[0], reverse=True):
        q = f"{queued:5.0f}s" if queued is not None else "    -"
        r = f"{ran:5.0f}s" if ran >= 0 else "  ..."
        out.append(f"  queued {q}  ran {r}  {name}  [{conclusion or 'in progress'}]")
    return out


def _api(path: str) -> dict:
    base = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
    request = urllib.request.Request(
        f"{base}{path}",
        headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Pre-merge budget")
    parser.add_argument("--check", help="the required check this job carries")
    parser.add_argument("--budget-seconds", type=int, default=BUDGET_SECONDS)
    parser.add_argument("--target-seconds", type=int, default=TARGET_SECONDS)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.check:
        parser.error("--check is required (or --selftest)")

    problems = shard_problems(json.loads(os.environ.get("NEEDS_JSON") or "{}"))
    repo, run, attempt = (os.environ.get(k) for k in ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    started, jobs = None, []
    try:
        started = _api(f"/repos/{repo}/actions/runs/{run}/attempts/{attempt}").get("run_started_at")
        jobs = _api(f"/repos/{repo}/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100").get("jobs", [])
    except Exception as exc:  # noqa: BLE001 — any failure to measure is the same answer
        print(f"pre-merge budget: could not read run {run} attempt {attempt}: {exc}", file=sys.stderr)
    now = datetime.datetime.now(datetime.timezone.utc)
    if (over := budget_problem(started, now, args.budget_seconds)) is not None:
        problems.append(over)

    begun = _when(started)
    elapsed = f"{(now - begun).total_seconds():.0f}s" if begun else "unmeasured"
    report = [
        f"pre-merge budget for {args.check!r}: {elapsed} (target {args.target_seconds}s, budget {args.budget_seconds}s)",
        *job_lines(jobs),
    ]
    print("\n".join(report))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write("```\n" + "\n".join(report) + "\n```\n")
    missed = target_warning(started, now, args.target_seconds)
    if missed is not None:
        print(f"::warning title=pre-merge target missed ({args.check})::{missed}")
    if problems:
        print(f"pre-merge budget: FAIL — {len(problems)} problem(s)", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("pre-merge budget: OK")
    return 0


def selftest() -> int:
    now = datetime.datetime(2026, 10, 28, 12, 4, 0, tzinfo=datetime.timezone.utc)
    ok = {"a": {"result": "success"}, "b": {"result": "success"}}
    cases = [
        ("every shard succeeded", shard_problems(ok), False),
        ("a failed shard", shard_problems({**ok, "c": {"result": "failure"}}), True),
        ("a skipped shard reads as a pass to GitHub, and fails here", shard_problems({"a": {"result": "skipped"}}), True),
        ("a cancelled shard", shard_problems({"a": {"result": "cancelled"}}), True),
        ("no shard at all", shard_problems({}), True),
        ("inside the budget", [p for p in [budget_problem("2026-10-28T12:00:30Z", now, 240)] if p], False),
        ("over the budget", [p for p in [budget_problem("2026-10-28T11:59:00Z", now, 240)] if p], True),
        ("an unmeasured run", [p for p in [budget_problem(None, now, 240)] if p], True),
        ("inside the target", [p for p in [target_warning("2026-10-28T12:00:30Z", now, 240)] if p], False),
        ("past the target, which warns", [p for p in [target_warning("2026-10-28T11:59:00Z", now, 240)] if p], True),
    ]
    failed = 0
    for label, problems, expect in cases:
        good = bool(problems) == expect
        print(f"  {'ok  ' if good else 'FAIL'}  {label}")
        failed += not good
    lines = job_lines([{"name": "slow", "created_at": "2026-10-28T12:00:00Z", "started_at": "2026-10-28T12:00:05Z",
                        "completed_at": "2026-10-28T12:03:05Z", "conclusion": "success"},
                       {"name": "running", "created_at": "2026-10-28T12:00:00Z", "started_at": None}])
    good = "ran   180s  slow" in lines[0] and "running" in lines[1]
    print(f"  {'ok  ' if good else 'FAIL'}  the job record lists each job's queue and run time, slowest first")
    failed += not good
    print(f"pre-merge budget self-test: {'PASS' if not failed else 'FAIL'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
