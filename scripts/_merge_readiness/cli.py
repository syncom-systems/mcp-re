# SPDX-License-Identifier: Apache-2.0
"""The command line: resolve the candidate, derive what it requires, decide, report."""

from __future__ import annotations

import argparse
import sys

from _merge_readiness.candidate import (
    changed_files,
    check_runs,
    gh_json,
    git,
    manifest_at,
    ruleset_required_checks,
)
from _merge_readiness.derivation import (
    checks_for_lanes,
    lane_scripts,
    pull_request_workflows,
    umbrella_checks,
)
from _merge_readiness.errors import Undecidable
from _merge_readiness.report import Outcome, report
from _merge_readiness.verdict import FAILED, NOT_READY, READY, decide, skipped_by_itself

import _affected  # noqa: E402
from _evidence import required_lanes  # noqa: E402

_EXIT = {READY: 0, NOT_READY: 1, FAILED: 2}
_RULESET_ONLY = "branch ruleset (no declared unit affected)"
_RULESET_AND_LANES = "branch ruleset + the pre-merge lane checks of the verification-unit closure"


def parser(description: str) -> argparse.ArgumentParser:
    arguments = argparse.ArgumentParser(description=description)
    arguments.add_argument("--sha", help="candidate commit; defaults to the PR head or HEAD")
    arguments.add_argument("--pr", help="resolve the candidate from this PR number")
    arguments.add_argument("--base", default="origin/main", help="merge base ref")
    arguments.add_argument("--repo", default="matssun/mcp-re")
    arguments.add_argument("--selftest", action="store_true")
    return arguments


def _candidate_sha(args: argparse.Namespace) -> str:
    sha = args.sha
    if args.pr and not sha:
        sha = gh_json("pr", "view", args.pr, "--repo", args.repo, "--json", "headRefOid")["headRefOid"]
    return git("rev-parse", sha or "HEAD")


def _closure_lanes(units: list[dict], affected: set[str]) -> set[str]:
    """The lanes the affected units' declared evidence claims."""
    lanes: set[str] = set()
    for unit in units:
        if unit["id"] in affected:
            lanes |= required_lanes(unit)
    return lanes


def _lane_requirements(
    lanes: set[str], changed: set[str], runs: dict[str, dict], sha: str
) -> tuple[dict[str, list[str]], list[str]]:
    """`(required, deferred)` for the closure's lanes.

    A lane no pre-merge job runs is deferred to the complete run. So is a lane whose every
    job reports itself SKIPPED: the bounded mutation probe skips when `select-units` defers
    the scope, and a job that succeeded having applied nothing would otherwise read as the
    lane measured.
    """
    resolved = checks_for_lanes(lanes, lane_scripts(), pull_request_workflows(changed))
    skipped = {
        lane for lane, names in resolved.items()
        if names and all(skipped_by_itself(runs.get(n), sha) for n in names)
    }
    unrun = {lane for lane, names in resolved.items() if not names}
    required = {lane: names for lane, names in resolved.items() if names and lane not in skipped}
    return required, sorted(unrun | skipped)


def _evaluate(args: argparse.Namespace) -> Outcome:
    sha = _candidate_sha(args)
    # From the CANDIDATE, never from the tree: see `manifest_at`.
    manifest = manifest_at(sha)
    units, edges = manifest.get("unit", []), manifest.get("edge", [])
    changed = changed_files(sha, args.base)
    affected = _affected.by_paths(units, edges, changed)
    lanes = _closure_lanes(units, affected)
    # The branch ruleset is ALWAYS required: "no lane was required" and "every required
    # lane passed" are different facts, so a closure that asks for nothing still leaves
    # the ruleset's checks. Lanes the closure requires add their pre-merge jobs to it.
    required = {name: [name] for name in ruleset_required_checks(args.repo, args.base)}
    runs = check_runs(args.repo, sha)
    deferred: list[str] = []
    authority = _RULESET_ONLY
    if lanes:
        authority = _RULESET_AND_LANES
        by_lane, deferred = _lane_requirements(lanes, changed, runs, sha)
        required.update(by_lane)
    state, rows = decide(required, runs, sha, umbrella_checks())
    return Outcome(sha, state, authority, rows, affected, len(units), deferred)


def run(args: argparse.Namespace) -> int:
    try:
        outcome = _evaluate(args)
    except Undecidable as exc:
        print(f"MERGE-READINESS: UNDECIDABLE — {exc}", file=sys.stderr)
        return 3
    report(outcome)
    return _EXIT[outcome.state]
