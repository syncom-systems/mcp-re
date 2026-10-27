#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verification-trigger gate — what starts exhaustive verification, and what cannot.

THE CONTRACT. Four workflows own the scheduling of assurance, and each has one job:

  pre-merge.yml      every pull request, no path filter. Bounded: structural gates, the Bazel
                     build and test, lint, SDK suites.
  post-merge.yml     every push to main: the same jobs again, on the merged result.
  mutation-probe.yml a pull request that moves a unit it can probe, bounded by a unit cap and a
                     timeout; anything it cannot bound is DEFERRED, never widened.
  verification.yml   the COMPLETE run. Only the weekly schedule and an explicit dispatch start
                     it. No `pull_request`, no `push`, no `paths:` filter.

A change may invalidate every piece of formal evidence — a toolchain bump moves all 314 unit
fingerprints — without authorizing the remeasurement. Invalidation is a fact the fingerprint
and `verify --gate` report (evidence STALE or MISSING, never verified); remeasuring is a
decision a person or a schedule takes. This gate holds the first apart from the second.

WHAT IT PROVES, from the workflows as written:

  1. `verification.yml`'s triggers are exactly `schedule` and `workflow_dispatch`, with no
     path filter, and no step of it scopes by `select-units` or falls back to a full run.
     Its first job refuses any other event, so a trigger added by mistake fails instead of
     measuring.
  2. No other workflow calls it (`uses:`), follows it (`workflow_run`) or dispatches it.
  3. `pre-merge.yml` starts on every pull request and is callable; `post-merge.yml` starts on
     push to main and calls it.
  4. `mutation-probe.yml` starts on no push, has a pull-request path filter, a job timeout of
     at most 30 minutes, a `--max-units` cap of at most 20, defers when `select-units` fails
     (a deferral SKIPS the `probe` job, so one that applied nothing never reads as measured),
     and installs no toolchain of its own.
  5. Negative controls, run against the real workflow files: a pull request or push that
     changes `MODULE.bazel`, a lockfile, the toolchain pin, the verification platform or the
     workflow itself starts no complete run, and the verification-platform paths that DO
     start the bounded probe are deferred by `select-units`.
  6. A wildcard-free path filter names something the tree holds or a lane reads.

WHAT IT DOES NOT PROVE: that any run passes, or that a lane measures what it claims. The
`aggregate` job must still run `verify --aggregate --gate`, which reports a missing record as
INCOMPLETE; this gate checks only that it does.

Run:  python3 scripts/verification_trigger_gate.py
      python3 scripts/verification_trigger_gate.py --selftest
"""

from __future__ import annotations

import functools
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"

sys.path.insert(0, str(REPO / "scripts"))
import workflow_reader  # noqa: E402
from workflow_reader import (  # noqa: E402
    Mapping,
    Scalar,
    Workflow,
    WorkflowSyntaxError,
    glob_matches,
)

#: The reader is a line parser over files of several hundred lines, and the selftest reads each
#: workflow once per control, so a text is parsed once.
parse = functools.lru_cache(maxsize=None)(workflow_reader.parse)
parse_yaml = functools.lru_cache(maxsize=None)(workflow_reader.parse_yaml)

sys.path.insert(0, str(REPO / "tools" / "verification"))
from _fingerprint import fingerprint_read_set  # noqa: E402
from _manifest import (  # noqa: E402
    ManifestError,
    load_assumptions,
    load_toolchains,
    load_trust_boundaries,
    load_verification,
)
import _affected  # noqa: E402
import _registries  # noqa: E402
from _registry_refs import structural_probe_paths  # noqa: E402

COMPLETE_EVENTS = {"schedule", "workflow_dispatch"}
PROBE_EVENTS = {"pull_request", "schedule", "workflow_dispatch"}
PROBE_MAX_TIMEOUT_MINUTES = 30
PROBE_MAX_UNITS = 20

#: What the negative controls change. Each is a path a complete run must not start on, from
#: either a pull request or a push to main.
CONTROL_PATHS = (
    "MODULE.bazel",
    "MODULE.bazel.lock",
    "bazel/crates.lock",
    "Cargo.lock",
    _registries.relative("toolchains"),
    _registries.relative("verification"),
    "tools/verification/verify",
    "scripts/install_pinned_verus.py",
    "mcp-re-core/src/lib.rs",
    ".github/workflows/verification.yml",
)

#: Paths where a bounded probe may start but `select-units` must defer, because the platform
#: that computes the scope is itself what changed.
PLATFORM_PATHS = (
    "tools/verification/_manifest.py",
    "tools/verification/verify-mutations",
    ".github/workflows/mutation-probe.yml",
)


def starts_on(text: str, event: str, path: str) -> bool:
    """Whether a `path` change delivered by `event` starts the workflow `text`, by GitHub's
    rule: the trigger exists and has no path filter, or a filter matching the path."""
    trigger = parse(text).triggers.get(event)
    if trigger is None:
        return False
    if trigger.paths is None:
        return True
    return any(glob_matches(pattern, path) for pattern in trigger.paths)


def _job_scalars(text: str, job: str, key: str) -> str | None:
    jobs = parse_yaml(text).get("jobs")
    body = jobs.get(job) if isinstance(jobs, Mapping) else None
    node = body.get(key) if isinstance(body, Mapping) else None
    return node.value if isinstance(node, Scalar) else None


def check_complete_run(text: str) -> list[str]:
    workflow = parse(text)
    failures: list[str] = []
    extra = sorted(set(workflow.triggers) - COMPLETE_EVENTS)
    missing = sorted(COMPLETE_EVENTS - set(workflow.triggers))
    if extra:
        failures.append(
            f"verification.yml declares {extra}: only `schedule` and `workflow_dispatch` may "
            "start the complete run, and an ordinary pull request or push never does"
        )
    if missing:
        failures.append(f"verification.yml no longer declares {missing}: the complete run needs both")
    failures += [
        f"verification.yml's `{trigger.name}` carries a path filter: a complete run is not "
        "started by what a change touches"
        for trigger in workflow.triggers.values()
        if trigger.filtered
    ]
    commands = " ".join(command.text for command in workflow.commands())
    if "select-units" in commands:
        failures.append(
            "verification.yml invokes `select-units`: it scopes a run to a change, and a scope "
            "that cannot be trusted must be deferred, not widened"
        )
    guard = workflow.jobs.get("scope")
    refusal = "\n".join(step.run.value for step in guard.steps if step.run) if guard else ""
    if "exit 1" not in refusal or "schedule|workflow_dispatch" not in refusal:
        failures.append(
            "verification.yml's `scope` job does not refuse every event but schedule and "
            "dispatch — a trigger added by mistake would measure instead of failing"
        )
    aggregate = workflow.jobs.get("aggregate")
    if aggregate is None or "--aggregate --gate" not in " ".join(c.text for c in aggregate.commands()):
        failures.append(
            "verification.yml's `aggregate` job does not run `verify --aggregate --gate`: the "
            "step that reports a missing record as INCOMPLETE is gone"
        )
    return failures


def check_bounded_probe(text: str) -> list[str]:
    workflow = parse(text)
    failures: list[str] = []
    extra = sorted(set(workflow.triggers) - PROBE_EVENTS)
    if extra:
        failures.append(
            f"mutation-probe.yml declares {extra}: a bounded probe runs on a pull request, and "
            "the complete run is weekly or dispatched, never a push to main"
        )
    pull_request = workflow.triggers.get("pull_request")
    if pull_request is None or not pull_request.paths:
        failures.append("mutation-probe.yml's `pull_request` has no path filter: the probe starts only on what it can invalidate")
    timeout = _job_scalars(text, "probe", "timeout-minutes")
    if timeout is None or not timeout.isdigit() or int(timeout) > PROBE_MAX_TIMEOUT_MINUTES:
        failures.append(
            f"mutation-probe.yml's `probe` job has timeout-minutes {timeout!r}; it must be an "
            f"integer of at most {PROBE_MAX_TIMEOUT_MINUTES}"
        )
    scope_timeout = _job_scalars(text, "scope", "timeout-minutes")
    if scope_timeout is None or not scope_timeout.isdigit() or int(scope_timeout) > PROBE_MAX_TIMEOUT_MINUTES:
        failures.append(f"mutation-probe.yml's `scope` job has timeout-minutes {scope_timeout!r}; it must be bounded")
    gate = _job_scalars(text, "probe", "if") or ""
    if "needs.scope.outputs.measure == 'true'" not in gate or _job_scalars(text, "probe", "needs") != "scope":
        failures.append(
            "mutation-probe.yml's `probe` job does not run only when `scope` decided to measure: a "
            "deferral must SKIP the check, because a job that succeeded having applied nothing "
            "reads as a measured lane to the merge-readiness gate"
        )
    commands = [command.text for command in workflow.commands()]
    selects = [c for c in commands if "select-units" in c]
    caps = [int(m.group(1)) for c in selects for m in re.finditer(r"--max-units\s+(\d+)", c)]
    if not selects or not caps or max(caps) > PROBE_MAX_UNITS:
        failures.append(
            f"mutation-probe.yml does not pass `select-units --max-units N` with N <= "
            f"{PROBE_MAX_UNITS}: an unbounded scope is a complete run in disguise"
        )
    if not any(re.search(r"if\s+!\s+python3\s+\S*select-units", c) for c in commands):
        failures.append(
            "mutation-probe.yml does not defer when `select-units` itself fails: a scope that "
            "cannot be computed must apply no probe, not stop the check or widen it"
        )
    failures += [
        f"mutation-probe.yml installs or selects a toolchain ({c.strip()[:60]!r}): every Rust "
        "member of a probe battery is a Bazel target under the compiler MODULE.bazel pins"
        for c in commands
        if re.search(r"\brustup\b|\bcargo\b", c)
    ]
    failures += [
        f"mutation-probe.yml uses `{step.uses}`, a floating toolchain installer"
        for job in workflow.jobs.values()
        for step in job.steps
        if step.uses and "rust-toolchain" in step.uses
    ]
    return failures


def check_merge_path(pre_merge: str, post_merge: str) -> list[str]:
    failures: list[str] = []
    pre = parse(pre_merge)
    trigger = pre.triggers.get("pull_request")
    if trigger is None or trigger.filtered:
        failures.append("pre-merge.yml must start on EVERY pull request: no `paths` or `paths-ignore`")
    if "workflow_call" not in pre.triggers:
        failures.append("pre-merge.yml is not callable: post-merge.yml cannot run it on main")
    post = parse(post_merge)
    push = post.triggers.get("push")
    if push is None or push.filtered:
        failures.append("post-merge.yml must start on every push to main: no path filter")
    if "pull_request" in post.triggers:
        failures.append("post-merge.yml declares `pull_request`: it is the after-merge run")
    calls = [text for job in parse(post_merge).jobs.values() for text in [job_uses(post_merge, job.key)] if text]
    if "./.github/workflows/pre-merge.yml" not in calls:
        failures.append("post-merge.yml does not call ./.github/workflows/pre-merge.yml")
    return failures


def job_uses(text: str, key: str) -> str | None:
    return _job_scalars(text, key, "uses")


def check_indirect(texts: dict[str, str]) -> list[str]:
    failures: list[str] = []
    for name, text in sorted(texts.items()):
        workflow: Workflow = parse(text)
        if "workflow_run" in workflow.triggers:
            failures.append(f"{name} declares `workflow_run`: a chained run is an indirect start")
        if name != "verification.yml":
            for key in workflow.jobs:
                if job_uses(text, key) == "./.github/workflows/verification.yml":
                    failures.append(f"{name}: job `{key}` calls verification.yml")
            for command in workflow.commands():
                if re.search(r"gh\s+workflow\s+run|/dispatches\b|gh\s+api\b[^\n]*workflows", command.text):
                    failures.append(f"{name}: dispatches a workflow ({command.text.strip()[:60]!r})")
    return failures


def stale_filters(workflow_text: str, repo: Path, required: list[str]) -> list[str]:
    """Wildcard-free `paths:` entries that name neither a file in the tree nor a fingerprint
    input. A filter that matches nothing is not a trigger; it is a claim about what re-runs
    the lane that stopped being true."""
    wanted = set(required)
    stale: list[str] = []
    for trigger in parse(workflow_text).triggers.values():
        for pattern in trigger.paths or ():
            if any(ch in pattern for ch in "*?[") or pattern in wanted:
                continue
            if not (repo / pattern).exists():
                stale.append(pattern)
    return sorted(set(stale))


def check_controls(verification: str, probe: str, deferral) -> list[str]:
    """The negative controls, as properties of the given workflow texts."""
    failures: list[str] = []
    for event in ("pull_request", "push"):
        for path in CONTROL_PATHS:
            if starts_on(verification, event, path):
                failures.append(f"a {event} changing {path} starts the complete run")
    for path in CONTROL_PATHS:
        if path.startswith("tools/verification/") or path.endswith("mutation-probe.yml"):
            continue
        if starts_on(probe, "push", path):
            failures.append(f"a push changing {path} starts the mutation probe")
    for path in PLATFORM_PATHS:
        if deferral([path]) is None:
            failures.append(f"select-units would scope a change to {path}, a platform file, instead of deferring")
    return failures


def all_failures(texts: dict[str, str], deferral, required: list[str]) -> list[str]:
    failures = check_complete_run(texts["verification.yml"])
    failures += check_bounded_probe(texts["mutation-probe.yml"])
    failures += check_merge_path(texts["pre-merge.yml"], texts["post-merge.yml"])
    failures += check_indirect(texts)
    failures += check_controls(texts["verification.yml"], texts["mutation-probe.yml"], deferral)
    failures += [
        f"mutation-probe.yml path filter {p!r} names nothing in the tree"
        for p in stale_filters(texts["mutation-probe.yml"], REPO, required)
    ]
    return failures


def read_texts() -> dict[str, str]:
    return {path.name: path.read_text(encoding="utf-8") for path in sorted(WORKFLOWS.glob("*.yml"))}


def fingerprint_inputs() -> list[str]:
    doc, toolchains = load_verification(), load_toolchains()
    assumptions, boundaries = load_assumptions(), load_trust_boundaries()
    required: set[str] = set()
    for unit in doc.get("unit", []):
        required |= fingerprint_read_set(unit, doc, toolchains, assumptions, boundaries)
    required |= set(structural_probe_paths(_registries.rows("structural-probes", "probe")))
    return sorted(required)


def selftest() -> int:
    failed = False
    texts = read_texts()
    deferral = _affected.platform_change
    # Deriving the fingerprint read set measures every unit (about a minute); the real run does
    # it, and the controls below need only the workflow files.
    required: list[str] = []
    base = all_failures(texts, deferral, required)

    def case(label: str, ok: bool, got: object = None) -> None:
        nonlocal failed
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            failed = True
            print(f"        got {got}")

    case("the real workflows satisfy the contract", not base, base)

    def mutate(name: str, old: str, new: str) -> dict[str, str]:
        assert old in texts[name], f"selftest anchor missing in {name}: {old!r}"
        return {**texts, name: texts[name].replace(old, new, 1)}

    verification_on = "on:\n  schedule:"
    controls = [
        ("a pull_request on MODULE.bazel starts the complete run",
         mutate("verification.yml", verification_on, 'on:\n  pull_request:\n    paths:\n      - "MODULE.bazel"\n  schedule:'),
         "MODULE.bazel starts the complete run"),
        ("a pull_request on the toolchain pin starts the complete run",
         mutate("verification.yml", verification_on, 'on:\n  pull_request:\n    paths:\n      - "verification/policy/toolchains.lock.toml"\n  schedule:'),
         "toolchains.lock.toml starts the complete run"),
        ("a pull_request on the verification platform starts the complete run",
         mutate("verification.yml", verification_on, 'on:\n  pull_request:\n    paths:\n      - "tools/verification/**"\n  schedule:'),
         "tools/verification/verify starts the complete run"),
        ("an unfiltered push starts the complete run",
         mutate("verification.yml", verification_on, "on:\n  push:\n  schedule:"),
         "declares ['push']"),
        ("workflow_run chains the complete run",
         mutate("verification.yml", verification_on, "on:\n  workflow_run:\n    workflows: [pre-merge]\n  schedule:"),
         "declares ['workflow_run']"),
        ("the schedule is removed",
         mutate("verification.yml", '  schedule:\n    - cron: "0 4 * * 0"\n', ""),
         "no longer declares ['schedule']"),
        ("the scope job stops refusing foreign events",
         mutate("verification.yml", "exit 1 ;;", "exit 0 ;;"),
         "does not refuse every event"),
        ("a select-units scope returns to the complete run",
         mutate("verification.yml", "echo \"complete run:", "python3 tools/verification/select-units --base HEAD^1 --out u; echo \"complete run:"),
         "invokes `select-units`"),
        ("the aggregate gate is dropped",
         mutate("verification.yml", "./tools/verification/verify --aggregate --gate", "./tools/verification/verify --aggregate"),
         "step that reports a missing record as INCOMPLETE is gone"),
        ("another workflow calls the complete run",
         {**texts, "post-merge.yml": texts["post-merge.yml"] + "  full:\n    uses: ./.github/workflows/verification.yml\n"},
         "calls verification.yml"),
        ("another workflow dispatches it",
         mutate("pre-merge.yml", "    steps:\n", "    steps:\n      - run: gh workflow run verification.yml\n"),
         "dispatches a workflow"),
        ("the probe returns to push",
         mutate("mutation-probe.yml", "on:\n  pull_request:", "on:\n  push:\n    branches: [main]\n  pull_request:"),
         "declares ['push']"),
        ("the probe loses its timeout",
         mutate("mutation-probe.yml", "timeout-minutes: 30", "timeout-minutes: 360"),
         "timeout-minutes '360'"),
        ("the probe job runs even when the scope deferred",
         mutate("mutation-probe.yml", "    if: needs.scope.outputs.measure == 'true'\n", ""),
         "does not run only when `scope` decided to measure"),
        ("the probe loses its unit cap",
         mutate("mutation-probe.yml", "--max-units 20 ", ""),
         "--max-units"),
        ("the probe stops deferring when scoping fails",
         mutate("mutation-probe.yml", "if ! python3 tools/verification/select-units", "python3 tools/verification/select-units"),
         "does not defer"),
        ("the probe reinstalls a floating toolchain",
         mutate("mutation-probe.yml", "      - name: Mutation-lane self-tests", "      - run: rustup toolchain install stable\n      - name: Mutation-lane self-tests"),
         "installs or selects a toolchain"),
        ("pre-merge gains a path filter",
         mutate("pre-merge.yml", "on:\n  pull_request:\n", 'on:\n  pull_request:\n    paths:\n      - "mcp-re-core/**"\n'),
         "EVERY pull request"),
        ("post-merge stops calling pre-merge",
         mutate("post-merge.yml", "uses: ./.github/workflows/pre-merge.yml", "uses: ./.github/workflows/weekly.yml"),
         "does not call ./.github/workflows/pre-merge.yml"),
    ]
    for label, mutated, expected in controls:
        failures = all_failures(mutated, deferral, required)
        case(label, any(expected in f for f in failures), failures)

    case("a PR changing MODULE.bazel starts pre-merge", starts_on(texts["pre-merge.yml"], "pull_request", "MODULE.bazel"))
    case("a platform change is deferred by select-units", deferral(["tools/verification/verify"]) is not None)
    case("an ordinary source change is not deferred as a platform change", deferral(["mcp-re-core/src/lib.rs"]) is None)
    glob = 'on:\n  pull_request:\n    paths:\n      - "mcp-re-proxy/src/tls_plane.rs"\n'
    case("a wildcard-free filter naming a moved file is STALE",
         stale_filters(glob, REPO, []) == ["mcp-re-proxy/src/tls_plane.rs"])
    case("an absent path that IS a fingerprint input is live, not stale",
         stale_filters(glob, REPO, ["mcp-re-proxy/src/tls_plane.rs"]) == [])

    if failed:
        print("verification-trigger gate: SELFTEST FAILED")
        return 1
    print("verification-trigger gate: selftest passed")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    try:
        required = fingerprint_inputs()
        texts = read_texts()
        failures = all_failures(texts, _affected.platform_change, required)
    except ManifestError as exc:
        print(f"verification-trigger gate: FAILED — the manifest does not load: {exc}")
        return 1
    except (WorkflowSyntaxError, KeyError) as exc:
        print(f"verification-trigger gate: FAILED — a workflow cannot be read: {exc!r}")
        return 1
    if not required:
        print("verification-trigger gate: FAILED — the fingerprint read set is empty")
        return 1
    if failures:
        print("verification-trigger gate: FAILED")
        for failure in sorted(set(failures)):
            print(f"  - {failure}")
        return 1
    print(
        f"verification-trigger gate: OK — verification.yml starts only on schedule and dispatch; "
        f"{len(CONTROL_PATHS)} control paths start no complete run from a pull request or push; "
        f"the bounded probe has a pull-request filter, a {PROBE_MAX_TIMEOUT_MINUTES}-minute timeout "
        f"and a {PROBE_MAX_UNITS}-unit cap; pre-merge starts on every pull request and "
        f"post-merge calls it; {len(texts)} workflows checked for indirect starts"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
