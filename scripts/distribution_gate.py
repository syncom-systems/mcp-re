#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Distribution gate — a tag may be distributed only if it names a qualified release.

The release identity is the immutable source revision a version tag points at. Distribution
(`.github/workflows/distribute.yml`) builds that revision and nothing else, and this gate is
the one place that decides whether the revision may be distributed at all:

1. the tag is a plain `vMAJOR.MINOR.PATCH` and resolves to a commit;
2. that commit is reachable from `origin/main` (a release is a commit of main);
3. `VERSION` at that commit equals the tag, so an archive named for the version carries it;
4. `docs/releases/<tag>-release-assurance.json` on `origin/main` records `PASS` for exactly
   that commit. The record is the output of the binding release-assurance lane
   (`release.yml`); `scripts/release_assurance_gate.py` separately proves it was produced
   by that lane. A tag whose record is absent, failing, or about another commit is refused,
   which is also what makes "distribute after qualification" a property rather than a habit.

On success it prints `key=value` lines (`version`, `sha`) for `$GITHUB_OUTPUT`.

WHAT THIS DOES NOT PROVE: that the binaries are good. Qualification is about the tree; the
archives are then built from that tree by Bazel under the pinned toolchains and checked by
the workflow's own verification jobs.

Run:  python3 scripts/distribution_gate.py --tag v0.19.0 [--repo DIR]
      python3 scripts/distribution_gate.py --selftest
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

TAG = re.compile(r"v(\d+\.\d+\.\d+)")
SHA = re.compile(r"[0-9a-f]{40}")


class Refused(Exception):
    """The tag may not be distributed; the message says why."""


def tag_version(tag: str) -> str:
    match = TAG.fullmatch(tag)
    if match is None:
        raise Refused(f"{tag!r} is not a release tag (vMAJOR.MINOR.PATCH)")
    return match.group(1)


def check_record(record: object, sha: str, tag: str) -> None:
    """The committed record is a PASS about exactly `sha`."""
    if not isinstance(record, dict):
        raise Refused(f"release-assurance record for {tag} is not an object")
    if record.get("verdict") != "PASS":
        raise Refused(f"release assurance for {tag} is {record.get('verdict')!r}, not 'PASS'")
    target = record.get("target")
    commit = target.get("commit") if isinstance(target, dict) else None
    if commit != sha:
        raise Refused(
            f"release assurance for {tag} qualified {commit!r}, but the tag points at {sha}"
        )


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    if done.returncode != 0:
        raise Refused(f"git {' '.join(args)}: {done.stderr.strip()}")
    return done.stdout.strip()


def resolve(tag: str, repo: Path) -> tuple[str, str]:
    version = tag_version(tag)
    sha = git(repo, "rev-parse", f"refs/tags/{tag}^{{commit}}")
    if SHA.fullmatch(sha) is None:
        raise Refused(f"{tag} resolved to {sha!r}, not a commit")
    ancestor = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", sha, "refs/remotes/origin/main"],
        check=False,
    )
    if ancestor.returncode != 0:
        raise Refused(f"{tag} ({sha}) is not reachable from origin/main")
    pinned = git(repo, "show", f"{sha}:VERSION").strip()
    if pinned != version:
        raise Refused(f"VERSION at {sha} is {pinned!r}, but the tag is {tag}")
    record = git(repo, "show", f"refs/remotes/origin/main:docs/releases/{tag}-release-assurance.json")
    try:
        check_record(json.loads(record), sha, tag)
    except json.JSONDecodeError as error:
        raise Refused(f"release-assurance record for {tag} is not JSON: {error}") from error
    return version, sha


def selftest() -> int:
    sha = "a" * 40
    cases = 0
    failures = 0

    def expect(name: str, ok: bool) -> None:
        nonlocal cases, failures
        cases += 1
        if not ok:
            failures += 1
            print(f"FAIL: {name}")

    def refused(call) -> bool:  # type: ignore[no-untyped-def]
        try:
            call()
        except Refused:
            return True
        return False

    expect("a plain tag parses", tag_version("v1.2.3") == "1.2.3")
    for bad in ("1.2.3", "v1.2", "v1.2.3-rc1", "v1.2.3 ", "latest", "../v1.2.3"):
        expect(f"tag {bad!r} refused", refused(lambda bad=bad: tag_version(bad)))
    good = {"verdict": "PASS", "target": {"commit": sha}}
    expect("a PASS about the commit is accepted", not refused(lambda: check_record(good, sha, "v1.2.3")))
    expect("another commit refused", refused(lambda: check_record(good, "b" * 40, "v1.2.3")))
    expect("a FAIL refused", refused(lambda: check_record({**good, "verdict": "FAIL"}, sha, "v1.2.3")))
    expect("no verdict refused", refused(lambda: check_record({"target": {"commit": sha}}, sha, "v1.2.3")))
    expect("no target refused", refused(lambda: check_record({"verdict": "PASS"}, sha, "v1.2.3")))
    expect("a non-object refused", refused(lambda: check_record([], sha, "v1.2.3")))
    if failures:
        print(f"{failures} of {cases} selftest cases failed")
        return 1
    print(f"selftest ok: {cases} cases")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--tag")
    parser.add_argument("--repo", default=".")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if not args.tag:
        parser.error("--tag is required")
    try:
        version, sha = resolve(args.tag, Path(args.repo))
    except Refused as refusal:
        print(f"distribution gate REFUSED: {refusal}", file=sys.stderr)
        return 1
    print(f"version={version}")
    print(f"sha={sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
