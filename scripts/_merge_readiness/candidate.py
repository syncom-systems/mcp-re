# SPDX-License-Identifier: Apache-2.0
"""What the gate reads about the candidate: its commit, registry, changed files and check runs."""

from __future__ import annotations

import json
import subprocess

from _merge_readiness.errors import Undecidable
from _merge_readiness.paths import REPO

import _registries  # noqa: E402
from _manifest import SCHEMA_VERSION  # noqa: E402

#: The registry whose `[[unit]]` entries decide which lanes a candidate needs.
VERIFICATION_TOML = _registries.relative("verification")


def git(*args: str) -> str:
    done = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise Undecidable(f"git {' '.join(args)}: {done.stderr.strip()}")
    return done.stdout.strip()


def _gh(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["gh", *args], capture_output=True, text=True)


def gh_json(*args: str):
    done = _gh(*args)
    if done.returncode != 0:
        raise Undecidable(f"gh {' '.join(args)}: {done.stderr.strip()}")
    return json.loads(done.stdout or "null")


def changed_files(sha: str, base: str) -> set[str]:
    merge_base = git("merge-base", base, sha)
    return set(git("diff", "--name-only", f"{merge_base}..{sha}").splitlines())


def _registry_blob(sha: str) -> dict:
    """The candidate's registry, parsed; absent or unparsable is `Undecidable`."""
    try:
        blob = _registries.text_at("verification", sha, REPO)
        if blob is None:
            raise Undecidable(f"{VERIFICATION_TOML} is absent at {sha[:12]}")
        return _registries.parse(blob, f"{VERIFICATION_TOML} at {sha[:12]}")
    except _registries.ManifestError as exc:
        raise Undecidable(str(exc)) from exc


def manifest_at(sha: str) -> dict:
    """The verification registry AS THE CANDIDATE CARRIES IT, not as the tree carries it.

    Every other fact this gate reads is bound to the commit under review: the candidate
    sha, its check runs, their conclusions. The required-lane SET was the exception — it
    came from `verification/policy/verification.toml` in the working tree — so a verdict
    was two tree states joined, and looked exactly like a correct one.

    It is not a theoretical hazard and it was not one-directional. Both shapes were
    measured in one campaign, in one workspace with two active PRs: 192 -> 197, where the
    tree carried MORE units than the candidate, and 212 -> 206, where it carried FEWER.
    Only the first is harmless. Deriving the required set from a SMALLER estate than the
    commit being merged is the shape that returns READY for a candidate whose real
    required set is larger, which is the one thing this gate exists to prevent.

    Read raw rather than through `load_verification`: that validator resolves each unit's
    `paths` globs against the CHECKED-OUT tree, so validating the candidate's registry from
    another branch would fail on files the candidate has and the tree does not — a tree
    fact again, in the one place that must carry none. The candidate's own lanes validate
    its registry; this gate needs its unit and edge tables and the one property whose drift
    would change what a lane MEANS:

      * `git show` failing (no such commit, or a candidate carrying no registry at all)
        and unparsable TOML both raise `Undecidable` — the brief's fallback (b), which
        costs nothing once the ESTATE comes from the candidate rather than the tree. Note
        the scope: this binds which units and which lanes to the candidate. The
        lane-to-check mapping (`_lanes.LANES`, `.github/workflows`) is still read from the
        working tree, so "every input comes from one commit" is not yet true of the whole
        verdict;
      * a `schema_version` this tooling does not implement is `Undecidable` for the same
        reason `load_verification` refuses it: the lane names would be read under a schema
        nobody here implements.
    """
    doc = _registry_blob(sha)
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise Undecidable(
            f"{VERIFICATION_TOML} at {sha[:12]} declares schema_version "
            f"{doc.get('schema_version')!r}; this gate implements {SCHEMA_VERSION}, so the "
            f"lanes its units require would be read under a schema nobody here implements"
        )
    return doc


def _started_after(run: dict) -> str:
    return run.get("started_at") or ""


def _supersedes(run: dict, prior: dict | None) -> bool:
    """Whether `run` replaces `prior` as the latest attempt under its name."""
    return prior is None or _started_after(run) >= _started_after(prior)


def check_runs(repo: str, sha: str) -> dict[str, dict]:
    """The latest check run per name at `sha`. Later attempts supersede earlier ones."""
    raw = _gh("api", "--paginate", f"repos/{repo}/commits/{sha}/check-runs?per_page=100",
              "--jq", ".check_runs[]")
    if raw.returncode != 0:
        raise Undecidable(f"gh api check-runs: {raw.stderr.strip()}")
    latest: dict[str, dict] = {}
    for line in filter(str.strip, raw.stdout.splitlines()):
        run = json.loads(line)
        if _supersedes(run, latest.get(run["name"])):
            latest[run["name"]] = run
    return latest


def _active_ruleset_ids(repo: str) -> list[str]:
    raw = _gh("api", f"repos/{repo}/rulesets", "--jq", '.[] | select(.enforcement == "active") | .id')
    if raw.returncode != 0:
        raise Undecidable(f"gh api rulesets: {raw.stderr.strip()}")
    return [line.strip() for line in raw.stdout.splitlines() if line.strip()]


def _ruleset_payload(repo: str, rid: str) -> dict | None:
    """One ruleset's detail, or `None` when it cannot be read."""
    detail = _gh("api", f"repos/{repo}/rulesets/{rid}", "--jq", "@json")
    if detail.returncode != 0:
        return None
    return json.loads(detail.stdout or "{}")


def _governs(payload: dict, branch: str) -> bool:
    """Whether the ruleset's ref conditions include `branch`; none listed means all."""
    include = payload.get("conditions", {}).get("ref_name", {}).get("include", [])
    wanted = ("~ALL", "~DEFAULT_BRANCH", f"refs/heads/{branch}")
    return not include or any(token in wanted for token in include)


def _required_contexts(payload: dict) -> set[str]:
    return {
        check["context"]
        for rule in payload.get("rules", [])
        if rule.get("type") == "required_status_checks"
        for check in rule.get("parameters", {}).get("required_status_checks", [])
        if check.get("context")
    }


def ruleset_required_checks(repo: str, base: str) -> list[str]:
    """The check contexts the repository's own ruleset requires on the target branch.

    Read from the API rather than transcribed, so this file holds no opinion about which
    checks are required and cannot drift from the ruleset. An empty or unreadable answer
    RAISES: a fallback authority that turns out to require nothing would make every
    unit-less change READY, which is the same false green the fallback exists to avoid.
    """
    branch = base.split("/")[-1]
    contexts: set[str] = set()
    for rid in _active_ruleset_ids(repo):
        payload = _ruleset_payload(repo, rid)
        if payload is not None and _governs(payload, branch):
            contexts |= _required_contexts(payload)
    if not contexts:
        raise Undecidable(
            f"no declared unit is affected and the ruleset for '{branch}' requires no status "
            "check, so nothing at all governs this candidate; decide it deliberately"
        )
    return sorted(contexts)
