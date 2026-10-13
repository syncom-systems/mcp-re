#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verification-trigger gate — the lane runs on everything its fingerprint reads.

WHAT THIS PROVES, exactly: three things about the trigger set.

  1. COVERAGE — every file that participates in an ADR-MCPRE-059 `ReviewFingerprint`,
     and every SITE a registered ADR-MCPRE-068 structural probe reads, is matched by
     `.github/workflows/verification.yml`'s `paths:` filters, on both the
     `pull_request` and `push` triggers. The fingerprint inputs are the read set
     `_fingerprint.fingerprint_read_set` records, never a list kept here.
  2. LIVENESS — no wildcard-free filter names a file that is neither in the tree nor a
     required fingerprint input.
  3. SYMMETRY — the `pull_request` and `push` filters are the same set. A path on one
     and not the other means a change the pull request measured and `main` did not, or
     the reverse, and a lane input that is not a fingerprint input (the prover
     installer, the negative controls) has no other clause to catch it.

The second clause of (2) is not slack: a fingerprint input may be absent from the tree
TODAY — a lockfile alternative, a declared path a split is about to create — and a filter
naming it is a live trigger for a shape the tree may take. A filter naming a path nothing
depends on and nothing occupies is the different thing: dead.

The second is not implied by the first, and MCPRE-175 is why it is here. When a file
becomes an owner subtree, the filter that named it keeps parsing, keeps matching
nothing, and fails nothing: `mcp-re-proxy/src/tls_plane.rs` sat in two workflows after
the file became `tls_plane/`. Coverage alone caught that only because the manifest also
named the moved paths — a split under a directory filter such as
`mcp-re-http-profile/src/**` would have left the dead entry invisible. A filter that
matches nothing is not a trigger; it is a claim about what re-runs the lane that stopped
being true.

WHAT IT DOES NOT PROVE: that the lane passes, that the trigger fires for a given
change, or that the fingerprint's component set is the right one. It proves only
that the trigger set is not NARROWER than the fingerprint set.

WHY IT MATTERS. A path-filtered workflow and a content-addressed fingerprint are
two independent lists of "what this evidence depends on", and they drift apart
silently — in the direction that produces a false green.

The dependency lock is in `_fingerprint.WORKSPACE_BUILD_INPUTS`, so a dependency
bump dirties every declared unit. When it was NOT in the workflow's trigger set,
Dependabot PR #532 (nine patch bumps across three lockfiles) would have merged
with every unit silently `DIRTY_SELF` and nothing re-running to notice. The
attestations on `main` would have kept reading FRESH over a dependency graph no
lane had measured.

`.github/workflows/mcp-re-supply-chain.yml` states the same rule for its own
trigger set: every file that decides the dependency graph re-triggers the gate.

Run:  python3 scripts/verification_trigger_gate.py
      python3 scripts/verification_trigger_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "verification.yml"

from workflow_reader import WorkflowSyntaxError, glob_matches, parse  # noqa: E402

sys.path.insert(0, str(REPO / "tools" / "verification"))
from _fingerprint import fingerprint_read_set  # noqa: E402
from _manifest import (  # noqa: E402
    ManifestError,
    load_assumptions,
    load_toolchains,
    load_trust_boundaries,
    load_verification,
)
import _registries  # noqa: E402
from _registry_refs import structural_probe_paths  # noqa: E402


def structural_probe_sites(probes: list[dict]) -> list[str]:
    """Every tree file a registered structural probe READS, derived from the registry.

    NOT a fingerprint input — no unit declares `structural://` before ADR-MCPRE-068 Phase
    0D, and the components land with those declarations. It belongs in the trigger set
    anyway, and for the same reason the fingerprint inputs do: an in-crate probe injects a
    module declaration into a parent it must not already contain, a boundary probe claims to
    correspond to a ```compile_fail doctest in a named file, and a relaxation edits named
    files to open the boundary. All are RE-ADJUDICATION triggers — change either and the probe may become stale, may start
    attacking a boundary that moved, or may silently stop being the case it cites — and a
    lane that does not re-run cannot report it.
    """
    return sorted(structural_probe_paths(probes))


def fingerprint_inputs() -> list[str]:
    """Every repo path a unit fingerprint reads, as the fingerprint itself reports it.

    Not reconstructed here. `_fingerprint.fingerprint_read_set` records what each unit's
    fingerprint actually digested, so a component added to the encoding is in this set the
    moment it reads a file, with nothing in this script to remember.
    """
    doc = load_verification()
    toolchains = load_toolchains()
    assumptions = load_assumptions()
    boundaries = load_trust_boundaries()
    required: set[str] = set()
    for unit in doc.get("unit", []):
        required |= fingerprint_read_set(unit, doc, toolchains, assumptions, boundaries)
    return sorted(required)


def stale_filters(workflow_text: str, repo: Path, required: list[str]) -> list[str]:
    """Wildcard-free `paths:` entries that name neither a file in the tree nor a required
    fingerprint input.

    A filter entry with no wildcard names exactly one path, so whether that path exists is
    decidable; anything with `*` is a pattern over files that may legitimately not exist
    yet. A path that IS a fingerprint input is live whether or not the tree holds it
    today — see the module docstring.
    """
    wanted = set(required)
    stale: list[str] = []
    for trigger in parse(workflow_text).triggers.values():
        for pattern in trigger.paths or ():
            if any(ch in pattern for ch in "*?["):
                continue
            if pattern in wanted:
                continue
            if not (repo / pattern).exists():
                stale.append(pattern)
    return sorted(set(stale))


def check(workflow_text: str, required: list[str]) -> list[str]:
    triggers = {
        name: (list(trigger.paths) if trigger.paths is not None else [])
        for name, trigger in parse(workflow_text).triggers.items()
    }
    failures: list[str] = [
        f"`{trigger.name}` filters with `paths-ignore:`, which names what does NOT start the "
        "lane; coverage of the fingerprint inputs cannot be read from it"
        for trigger in parse(workflow_text).triggers.values()
        if trigger.paths_ignore is not None and trigger.name in ("pull_request", "push")
    ]
    for trigger in ("pull_request", "push"):
        patterns = triggers.get(trigger)
        if patterns is None:
            failures.append(f"the workflow declares no `{trigger}` trigger")
            continue
        if not patterns:
            continue  # no `paths:` filter at all means every change triggers it
        for path in required:
            if not any(glob_matches(p, path) for p in patterns):
                failures.append(
                    f"{trigger}: no path filter matches {path!r}, which participates in "
                    "the ReviewFingerprint or is read by a registered probe — a change to "
                    "it leaves units the lane would then not re-measure"
                )
    pull_request, push = triggers.get("pull_request"), triggers.get("push")
    if pull_request is None or push is None:
        return failures
    if bool(pull_request) != bool(push):
        filtered = "pull_request" if pull_request else "push"
        unfiltered = "push" if pull_request else "pull_request"
        failures.append(
            f"`{filtered}` has a path filter and `{unfiltered}` has none — the two "
            "triggers must re-run the lane on the same changes, or main and its pull "
            "requests measure different things"
        )
    elif set(pull_request) != set(push):
        for path in sorted(set(pull_request) ^ set(push)):
            only = "pull_request" if path in pull_request else "push"
            failures.append(
                f"path filter {path!r} is on `{only}` only — the two triggers must re-run "
                "the lane on the same changes, or main and its pull requests measure "
                "different things"
            )
    return failures


def selftest() -> int:
    failed = False
    required = ["Cargo.lock", "mcp-re-core/src/time.rs"]
    cases = [
        ("both triggers cover every input", "on:\n  pull_request:\n    paths:\n      - \"Cargo.lock\"\n      - \"mcp-re-core/src/**\"\n  push:\n    paths:\n      - \"Cargo.lock\"\n      - \"mcp-re-core/src/**\"\n", ""),
        ("a fingerprint input missing from the filter", "on:\n  pull_request:\n    paths:\n      - \"mcp-re-core/src/**\"\n  push:\n    paths:\n      - \"mcp-re-core/src/**\"\n", "Cargo.lock"),
        ("covered on pull_request but not on push", "on:\n  pull_request:\n    paths:\n      - \"Cargo.lock\"\n      - \"mcp-re-core/src/**\"\n  push:\n    paths:\n      - \"mcp-re-core/src/**\"\n", "push: no path filter matches 'Cargo.lock'"),
        ("no paths filter means everything triggers", "on:\n  pull_request:\n  push:\n", ""),
        ("a single star must not cross a separator", "on:\n  pull_request:\n    paths:\n      - \"mcp-re-core/*\"\n      - \"Cargo.lock\"\n  push:\n    paths:\n      - \"mcp-re-core/*\"\n      - \"Cargo.lock\"\n", "mcp-re-core/src/time.rs"),
        ("a filter on pull_request only is asymmetric", "on:\n  pull_request:\n    paths:\n      - \"Cargo.lock\"\n      - \"mcp-re-core/src/**\"\n      - \"scripts/install.py\"\n  push:\n    paths:\n      - \"Cargo.lock\"\n      - \"mcp-re-core/src/**\"\n", "'scripts/install.py' is on `pull_request` only"),
        ("a filtered trigger beside an unfiltered one is asymmetric", "on:\n  pull_request:\n    paths:\n      - \"Cargo.lock\"\n      - \"mcp-re-core/src/**\"\n  push:\n", "`pull_request` has a path filter and `push` has none"),
        ("an unfiltered trigger beside a filtered one is asymmetric", "on:\n  pull_request:\n  push:\n    paths:\n      - \"Cargo.lock\"\n      - \"mcp-re-core/src/**\"\n", "`push` has a path filter and `pull_request` has none"),
        # The parser's own false positive: a comment between two entries used to
        # end the list, so the gate reported a gap the workflow did not have.
        ("a comment inside the list does not truncate it", "on:\n  pull_request:\n    paths:\n      - \"mcp-re-core/src/**\"\n      # why the next one is here\n      - \"Cargo.lock\"\n  push:\n    paths:\n      - \"mcp-re-core/src/**\"\n\n      - \"Cargo.lock\"\n", ""),
    ]
    for label, text, expected in cases:
        failures = check(text, required)
        ok = not failures if not expected else any(expected in f for f in failures)
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            failed = True
            print(f"        got {failures}")

    # The structural-probe derivation. A site read by a probe and covered by no filter is
    # a probe that cannot be re-adjudicated when the code under it moves, and the failure
    # is silent: the lane simply does not run.
    probes = [
        {"id": "S1", "insertion_parent": "a/src/mod.rs"},
        {"id": "S2", "doc_path": "b/src/lib.rs", "relaxation": [{"path": "c/src/owner.rs"}]},
    ]
    sites = structural_probe_sites(probes)
    ok = sites == ["a/src/mod.rs", "b/src/lib.rs", "c/src/owner.rs"]
    print(f"  {'ok  ' if ok else 'FAIL'}  a probe's injection, documented and relaxed sites are required inputs")
    if not ok:
        failed = True
        print(f"        got {sites}")
    uncovered = check('on:\n  pull_request:\n    paths:\n      - "z/**"\n  push:\n    paths:\n      - "z/**"\n', sites)
    ok = any("a/src/mod.rs" in f for f in uncovered)
    print(f"  {'ok  ' if ok else 'FAIL'}  an uncovered probe site fails the gate")
    if not ok:
        failed = True
    ok = structural_probe_sites([]) == []
    print(f"  {'ok  ' if ok else 'FAIL'}  no registered probe contributes no requirement")
    if not ok:
        failed = True

    # LIVENESS. A filter that matches nothing fails nothing, which is why it needs its
    # own control: coverage cannot see it.
    live = REPO
    liveness_cases = [
        (
            "a wildcard-free filter naming a file that exists is live",
            'on:\n  pull_request:\n    paths:\n      - "Cargo.lock"\n',
            [],
            [],
        ),
        (
            "a wildcard-free filter naming a moved file is STALE",
            'on:\n  pull_request:\n    paths:\n      - "mcp-re-proxy/src/tls_plane.rs"\n',
            [],
            ["mcp-re-proxy/src/tls_plane.rs"],
        ),
        (
            "the subtree pattern that replaced it is not read as a literal",
            'on:\n  pull_request:\n    paths:\n      - "mcp-re-proxy/src/tls_plane/**"\n',
            [],
            [],
        ),
        (
            "an absent path that IS a fingerprint input is live, not stale",
            'on:\n  pull_request:\n    paths:\n      - "mcp-re-proxy/tests/integration.rs"\n',
            ["mcp-re-proxy/tests/integration.rs"],
            [],
        ),
    ]
    for label, text, wanted, expected in liveness_cases:
        got = stale_filters(text, live, wanted)
        ok = got == expected
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            failed = True
            print(f"        got {got}, expected {expected}")

    if failed:
        print("verification-trigger gate: SELFTEST FAILED")
        return 1
    print("verification-trigger gate: selftest passed")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()

    try:
        inputs = fingerprint_inputs()
    except ManifestError as exc:
        print(f"verification-trigger gate: FAILED — the manifest does not load: {exc}")
        return 1
    if not inputs:
        print("verification-trigger gate: FAILED — the fingerprint read set is empty")
        return 1
    required = sorted(set(inputs) | set(structural_probe_sites(_registries.rows("structural-probes", "probe"))))
    text = WORKFLOW.read_text(encoding="utf-8")
    try:
        failures = check(text, required)
    except WorkflowSyntaxError as exc:
        print(f"verification-trigger gate: FAILED — {WORKFLOW.name} cannot be read: {exc}")
        return 1
    failures += [
        f"path filter {p!r} names nothing in the tree — a filter that matches nothing is "
        "not a trigger, and a file that became an owner subtree leaves exactly this behind"
        for p in stale_filters(text, REPO, required)
    ]
    if failures:
        print("verification-trigger gate: FAILED")
        for failure in sorted(set(failures)):
            print(f"  - {failure}")
        return 1
    # The examined scope is printed, not just the verdict: a run that derived an
    # empty required-set would otherwise report OK for having checked nothing.
    print(
        f"verification-trigger gate: OK — {len(required)} fingerprint input(s) and "
        f"structural-probe site(s) all matched by the pull_request and push filters, the "
        f"two filter sets are identical, and every wildcard-free filter names something "
        f"the tree holds or a lane reads"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
