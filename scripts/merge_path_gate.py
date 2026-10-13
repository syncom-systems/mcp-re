#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Merge-path gate — a control the assurance model relies on must run on the merge path.

THE FAILURE CLASS, which is the reason this file exists rather than any single instance:

    A security/assurance control relied upon by the assurance model must be mechanically
    present on the required merge path. Existence in a local-only aggregate such as
    `scripts/local_gate.sh` does not establish enforcement.

`local_gate.sh` is a convenience aggregate that a developer chooses to run. A control
reachable only from it is enforced by remembering to run it, which is the same standing as
no control at all — with the added cost that the repository, its docs and its reviewers all
believe the control is enforced. That belief is the damage: every claim above a control
reads as measured while nothing measured the change.

It has happened repeatedly and was never noticed by the thing that failed:

  * the two ADR-MCPRE-061 ratchets — a PR could grow a registered file or a lint baseline;
  * `verification_trigger_gate.py` — a PR narrowing the trigger filter also disabled the
    check that polices the filter;
  * `registry_approval_gate.py` — RED on `main`, with every CI check on every PR green;
  * the ten `tools/verification/test_*.py` suites, which are the assurance platform's own
    self-tests: nothing on the merge path established that the verdict algebra, the
    invalidation rules, the escape-hatch detector or the views generator still behave as
    the ADR says.

Each was repaired one at a time, by someone noticing. This gate is what notices.

WHAT IT PROVES: every script `local_gate.sh` invokes is named by at least one workflow
under `.github/workflows/`, or is exempt for a stated reason — AND that every control
invoked in COMMAND POSITION is executable in the index — AND that every ASSURANCE-PLATFORM
ENTRY POINT is reached by a workflow or by a dispatcher that one reaches.

THE DISCOVERY POPULATION IS A DEFINITION, which is the third half and the newest. The first
two sets are `local_gate.sh`'s invocations and `glob("tools/verification/test_*.py")`, and
NEITHER IS A DEFINITION — they are two places someone thought to look. That is not a
stylistic complaint; it is the measured reason this gate could not see its own blind spot.
`test_mutation_lane.py` was in neither set, and the repair was to add the second one: one
filename shape, closing one hole. The next shape was an extensionless entry point, and
`SELFTEST_GLOB` cannot match `check-generated`, `verify-tests` or `attest` any more than the
`local_gate.sh` scan could see a control that aggregate does not invoke.

So the population is defined rather than listed:

    An assurance-platform ENTRY POINT is an executable regular file directly under
    `tools/verification/` whose name does not begin with `_`.

The execute bit is the definition, and it is chosen because it is exactly what makes a file
invocable as a program — so the census is COMPLETE BY CONSTRUCTION. A new entry point cannot
be added without it (the `not_executable` half below already refuses one committed without
it), a leading underscore marks a module that is imported rather than run, and no filename
convention has to be remembered by anyone.

REACHED, not merely named. An entry point is on the merge path when an unconditional workflow
names it, or when a DISPATCHER that is itself reached runs it. There is one dispatcher:
`tools/verification/verify`, whose `LANES` table is where a lane's entry point is written
down. That table is read FROM THE DISPATCHER rather than pattern-matched out of it — a lane
silently leaving `LANES` is exactly the defect this half must catch, and a regex over the
file would match the line that remained in a comment.

Reading a dispatcher by import executes its module level, so this is deliberately ONE
dispatcher whose module level is pure (a table, a phase map, and two asserts) and not a
general mechanism. A gate that imported every control to discover edges would be running
them.

The second half is the same failure class read one step earlier. A control that cannot
START is not enforced, however many workflows name it, and the failure is not subtle when
it happens — `Permission denied`, stage 1, every run. It is subtle in the INDEX:
`tools/verification/evidence-class-census` landed at mode 100644, and nothing noticed,
because the gate above it matches only `.py` and `.sh` paths and every other control in
this repository happens to have been committed with its bit set. A path invoked as
`python3 x.py` needs no bit and is not asked for one; a path invoked as itself is.

A workflow must name its controls LITERALLY. This gate reads paths, so a step that
assembles a script name at run time — a shell loop over a list of suites, say — is a
control it cannot see, and an invisible control is how the next instance of this class
gets missed. Legibility to the checker is part of the enforcement.

WHAT IT DOES NOT PROVE: that the workflow naming it is a REQUIRED check, that the job runs
on every PR, or that the control is correct. Branch protection is repository configuration
and is not readable from the tree; this gate closes the gap it can see from here, which is
the one that has actually opened five times.

AND IT DOES NOT PROVE A DEFINED POPULATION FOR `scripts/`, which is stated rather than
quietly left out. The entry-point half above rests on a property — the execute bit — that
decides membership on its own. `scripts/` has no such property: it holds gates, a sourced
toolchain shim, a demo runner, architecture reports and CI helpers, and executability
separates none of them. The obvious substitute is a `*_gate.py` glob, and that is exactly
the move SF-010 warns against: it would repeat the `test_mutation_lane.py` repair one shape
later and leave the same hole for the next shape.

Measured 2026-09-21, so the gap is known rather than assumed: 41 files match
`scripts/*_gate.py`; 40 are invoked by `local_gate.sh` and therefore in the first
population; the one that is not, `merge_readiness_gate.py`, is named by an unconditional
workflow and belongs there — it is a merge-TIME authority, and running it from a pre-merge
aggregate would be asking a question about a commit that does not exist yet. So there is no
live instance today. What is missing is the guarantee, and a filename pattern would be a
guarantee-shaped thing rather than one.

Run:  python3 scripts/merge_path_gate.py
      python3 scripts/merge_path_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from workflow_reader import Command, Workflow, named_paths, parse, shell_commands, workflows

REPO = Path(__file__).resolve().parent.parent
LOCAL_GATE = REPO / "scripts" / "local_gate.sh"

#: A fetch that TRUNCATES the object graph rather than extending it.
#:
#: `git fetch --depth=N` into a full clone does not add a ref beside the history; it makes
#: the repository SHALLOW at that commit, and every later step that asks an ancestry
#: question gets the wrong answer. That is not a local mistake: it took the R9 linkage
#: control down with it, reporting all 56 recorded closure commits — present in the clone —
#: as merges the tree does not contain.
#:
#: Refused only in a job that checked out at `fetch-depth: 0`, because that job asked for
#: the full history on purpose and something later reads it. A job that never had the
#: history is free to fetch what it needs.
SHALLOW_FETCH = re.compile(r"git fetch\b[^\n]*(--depth[= ]|--shallow-since|--shallow-exclude)")

#: Scripts that are deliberately local, each with the reason. The exemption list IS part of
#: what this gate measured, so it is printed on every run and checked for dead entries: an
#: exemption naming a script the gate no longer invokes is a claim about nothing.
EXEMPT: dict[str, str] = {
    # Measurement lanes, not controls. Both refuse to run unattended for reasons of their
    # own — one needs a quiet box, the other a live process — and neither decides whether
    # a change is admissible.
    #
    # The SLO lane DOES run in CI now: `.github/workflows/slo.yml` schedules it on the
    # self-hosted runner. It stays exempt for two reasons, and both are the shape this list
    # is for rather than a way around it. That workflow is `paths:`-filtered on the declared
    # performance surface deliberately — a whole SLO run belongs where perf-relevant code was
    # touched, and `slo_evidence_identity.py` refuses a filter narrower than that surface, so
    # the filter is policed rather than trusted. And the workflow invokes the lane through
    # `scripts/local_gate.sh --from 4`, because stage 4 is a procedure (decide, refuse below
    # the disk floor, measure, attest only a PASS) with one definition; so this path is not
    # named literally there either.
    "scripts/local_slo_lane.sh": (
        "an SLO measurement, not an admissibility control; scheduled by the surface-filtered "
        ".github/workflows/slo.yml via local_gate.sh stage 4"
    ),
    # A PLUMBING rehearsal, and the only lane that needs a live kind cluster plus a 3 GB
    # bench image — neither exists on a CI runner. What keeps it wired is not this gate but
    # `rehearsal_claim_gate.py`, which IS unconditional: it fails if the runbooks' sentence
    # about this rehearsal stops being backed by a reachable invocation.
    "tools/slo/rehearse_job_spec.sh": (
        "a kind-cluster Job-spec rehearsal; its wiring is policed by rehearsal_claim_gate.py"
    ),
    "scripts/demo-local.sh": "a demo runner, not a control",
    # Architecture ANALYSIS. These report numbers for a human to classify — ADR-MCPRE-060
    # is explicit that the workflow is measure, validate, classify, review, and never
    # "run script, refactor until the number falls". A report has no pass to enforce, and
    # only their `--selftest` runs in the gate, which is a check that the measurement still
    # measures.
    "scripts/module_map.py": "an architecture report with no verdict; --selftest only",
    "scripts/startup_backedges.py": "an architecture report with no verdict; --selftest only",
    # Named only by the `paths:`-filtered verification workflow, and correctly so: it
    # checks the self-hosted runner's environment for that workflow's jobs. Its scope IS
    # that filter — there is no other job whose environment it describes — which is the
    # one shape the filtered-only rule below is meant to admit rather than refuse.
    "scripts/verification_runner_preflight.sh": (
        "a runner-environment preflight whose scope is the verification workflow itself"
    ),
}


def scripts_in(commands: list[Command]) -> set[str]:
    """The `.py`/`.sh` repository scripts these commands invoke, in any argument position.

    Commands, not text: the reader has dropped comments and usage lines, so a script a
    comment explains is not a script a step runs.
    """
    return {
        path
        for command in commands
        for path in named_paths(command.executed)
        if path.endswith((".py", ".sh"))
    }


def invoked_by(path: Path) -> set[str]:
    return scripts_in(shell_commands(path.read_text(encoding="utf-8")))


def pull_request_reach(workflow: Workflow) -> str | None:
    """`"every"` when this workflow starts on every pull request, `"filtered"` when on only
    some, `None` when on none.

    The merge path is the pull request. A workflow started only by a push to `main`, a
    schedule or a dispatch runs after the change it would refuse has merged, or never, so a
    control it names is on no merge path at all — however unfiltered its triggers are.
    """
    trigger = workflow.triggers.get("pull_request")
    if trigger is None:
        return None
    return "filtered" if trigger.filtered else "every"


def workflow_coverage() -> tuple[set[str], set[str]]:
    """`(named by an UNCONDITIONAL workflow, named only by a path-filtered one)`.

    The split is the second half of this gate's own failure class, and it was missing.
    Being NAMED by a workflow was treated as coverage, whatever that workflow's trigger —
    so a control could sit inside a `paths:`-filtered workflow, run on the PRs that touched
    those paths, and run on no others, while this gate reported it enforced. That is the
    same defect one level up: the filter and the set of changes the control must see are
    one dependency written down twice, and when they diverge nothing goes red, the job
    simply does not start.

    It was not hypothetical. `tools/verification/test_mutation_lane.py` — the self-test for
    the mutation lane's verdict semantics — was in neither `local_gate.sh` nor any
    unconditional workflow, and was invisible here because `mutation-probe.yml` mentions it.
    """
    unconditional: set[str] = set()
    only_filtered: set[str] = set()
    for workflow in workflows(REPO):
        reach = pull_request_reach(workflow)
        if reach is not None:
            target = unconditional if reach == "every" else only_filtered
            target |= scripts_in(workflow.commands())
    return unconditional, only_filtered - unconditional


#: The assurance platform's own self-tests. They are what establishes that a `verify`
#: verdict means what ADR-MCPRE-059 says it means, so every product claim rests on them —
#: which is why their scope here is NOT "whatever local_gate.sh happens to invoke". A suite
#: nobody wired into either aggregate would otherwise be enforced by nothing and visible to
#: nothing, and that is exactly how `test_mutation_lane.py` came to be neither.
SELFTEST_GLOB = "tools/verification/test_*.py"


def defects(
    gated: set[str],
    covered: set[str],
    exempt: dict[str, str],
    filtered_only: set[str] | None = None,
    selftests: set[str] | None = None,
) -> list[str]:
    """Controls the merge path does not run, and exemptions that name nothing."""
    filtered_only = filtered_only or set()
    found: list[str] = []
    for script in sorted(gated - covered - exempt.keys()):
        if script in filtered_only:
            found.append(
                f"{script} is named only by a `paths:`-filtered workflow. It therefore runs "
                f"on the pull requests that touch those paths and on no others, while "
                f"reading as enforced. Move it to an unconditional job, or add it to EXEMPT "
                f"with the reason its scope really is that filter."
            )
            continue
        found.append(
            f"{script} runs only in scripts/local_gate.sh. A control the assurance model "
            f"relies on must be present on the merge path; add it to a workflow, or add it "
            f"to EXEMPT with the reason it is deliberately local."
        )
    for script in sorted((selftests or set()) - covered - exempt.keys()):
        found.append(
            f"{script} is an assurance-platform self-test that no unconditional workflow "
            f"names. These suites are what establishes that a `verify` verdict means what "
            f"ADR-MCPRE-059 says it means; one that runs conditionally, or not at all, "
            f"leaves that meaning unestablished on every pull request that does not trip "
            f"its filter."
        )
    found.extend(
        f"EXEMPT names {script}, which scripts/local_gate.sh does not invoke. A dead "
        f"exemption is a claim about nothing and hides the next one that matters."
        for script in sorted(exempt.keys() - gated - (selftests or set()))
    )
    return found


#: Where the assurance platform's entry points live. One directory, because that is what
#: "the assurance platform" means in this tree and a definition that ranged wider would be
#: a guess about where the next one might go.
ENTRY_ROOT = "tools/verification"


def entry_points(root: Path) -> set[str]:
    """Every assurance-platform entry point under `root`, by the definition above.

    Executable, a regular file, directly under the directory, and not `_`-prefixed. Taking
    `root` as an argument is what lets the selftest below point this at a temporary tree and
    assert the DEFINITION — that the execute bit is the discriminator and the filename is
    not — instead of re-implementing the rule and agreeing with itself.
    """
    import os

    directory = root / ENTRY_ROOT
    if not directory.is_dir():
        return set()
    return {
        f"{ENTRY_ROOT}/{path.name}"
        for path in directory.iterdir()
        if path.is_file()
        and not path.name.startswith("_")
        and os.access(path, os.X_OK)
    }


def names_in(commands: list[Command]) -> set[str]:
    """Every `tools/verification/` entry point these commands name, extension or not.

    Distinct from `scripts_in`, which is anchored on `.py`/`.sh` and so cannot see
    `verify-tests`, and from `command_position_paths`, which asks whether a path runs AS
    A PROGRAM. Neither answers *does a workflow name this control*.
    """
    return {
        path
        for command in commands
        for path in named_paths(command.executed)
        if path.startswith(f"{ENTRY_ROOT}/")
    }


def workflow_entry_coverage(root: Path) -> tuple[set[str], set[str]]:
    """`(entry points named by an UNCONDITIONAL workflow, named only by a filtered one)`."""
    unconditional: set[str] = set()
    only_filtered: set[str] = set()
    for workflow in workflows(root):
        reach = pull_request_reach(workflow)
        if reach is not None:
            target = unconditional if reach == "every" else only_filtered
            target |= names_in(workflow.commands())
    return unconditional, only_filtered - unconditional


def dispatched_entry_points(root: Path) -> tuple[set[str], str | None]:
    """The lane entry points `verify` runs, read from its own `LANES` table.

    `(reached, problem)`. A problem is a FAILURE and never a silent empty set: if this
    gate cannot read the one edge source it has, every lane entry point becomes an orphan
    and the run would report nine defects with one cause. Naming the cause once is the
    honest report, and a gate that quietly returned `set()` here would instead be the
    "green that measured nothing" shape with the sign flipped.
    """
    dispatcher = root / ENTRY_ROOT / "verify"
    if not dispatcher.is_file():
        return set(), f"{ENTRY_ROOT}/verify does not exist, so no lane has a known runner"
    previous = list(sys.path)
    sys.path.insert(0, str(root / ENTRY_ROOT))
    try:
        from _load_tool import load_tool

        module = load_tool("verify", "_merge_path_gate_verify", root / ENTRY_ROOT)
        lanes = getattr(module, "LANES", None)
        if not lanes:
            return set(), f"{ENTRY_ROOT}/verify declares no LANES table"
        return {f"{ENTRY_ROOT}/{script}" for _name, script, _formal in lanes}, None
    except Exception as exc:  # noqa: BLE001 - any failure to read the table is the same answer
        return set(), f"{ENTRY_ROOT}/verify's LANES table could not be read: {exc!r}"
    finally:
        sys.modules.pop("_merge_path_gate_verify", None)
        sys.path[:] = previous


#: Entry points that are deliberately NOT admissibility controls, each with the reason.
#:
#: Same contract as `EXEMPT`: printed on every run and checked for dead entries, because an
#: exemption naming a file that no longer exists is a claim about nothing. The recurring
#: shapes here are GENERATOR, REPORT and MEASUREMENT — a program with no verdict cannot
#: refuse a change, so requiring it on the merge path would be requiring a run whose outcome
#: nothing reads.
EXEMPT_ENTRY: dict[str, str] = {
    # An evidence WRITER. It issues freshness records from measurements the lanes already
    # made; it decides nothing about admissibility, and the lanes that call it are reached.
    f"{ENTRY_ROOT}/attest": "an evidence writer invoked by the lanes; it issues records, it does not decide",
    # A one-command driver over phases CI deliberately runs as separate steps, so that a
    # phase which could not execute is visible as a missing record rather than folded into
    # one exit status.
    f"{ENTRY_ROOT}/evidence": "a driver over phases the merge path runs as separate steps",
    f"{ENTRY_ROOT}/evidence-graph": "a semantic overlay report with no verdict",
    f"{ENTRY_ROOT}/fingerprint": "a CLI over _fingerprint.fingerprint_unit; a measurement, not a verdict",
    # Its verdict half is `check-views`, which IS named by an unconditional workflow. A
    # generator and the gate over its output are two propositions, and only one of them
    # can refuse a change.
    f"{ENTRY_ROOT}/generate-views": "a generator; the verdict over its output is check-views",
    # The one case the filtered-only rule is meant to ADMIT rather than refuse: Charon links
    # the private rustc crates, so this cannot execute outside the pinned extraction
    # container, and the workflow whose filter it sits behind is the only place that exists.
    f"{ENTRY_ROOT}/regenerate-lean": "runs only inside the pinned extraction container, which one filtered workflow provides",
    # It reads the attestation store, which is machine-local and gitignored — so a
    # merge-path job cannot see what it would report. Its BINDING closure mode is policed
    # by scripts/release_assurance_gate.py, which is unconditional.
    f"{ENTRY_ROOT}/review": "reads the machine-local attestation store; its binding mode is policed by release_assurance_gate.py",
    f"{ENTRY_ROOT}/review-frontier": "a review-obligation report with no verdict",
    # It decides a pull request's SCOPE, never a verdict, and only in the two filtered
    # workflows that run the lanes it scopes — a scope is meaningless where no lane runs.
    # On any doubt it widens to a full run. Its semantics are pinned by
    # test_scoped_verification.py, which the unconditional ci.yml runs.
    f"{ENTRY_ROOT}/select-units": "scopes the filtered verification workflows; pinned by test_scoped_verification.py in ci.yml",
    f"{ENTRY_ROOT}/review-packet": "a derived review packet; a document, not a decision",
    # The lane dispatcher. It runs in verification.yml and nowhere else on a pull request,
    # and that workflow's path filter is not a guess: verification_trigger_gate.py, which IS
    # unconditional, holds it to every unit's fingerprint read set. So the dispatcher runs on
    # exactly the changes that move a unit, and its scope IS that filter.
    f"{ENTRY_ROOT}/verify": "the lane dispatcher; runs in verification.yml, whose filter verification_trigger_gate.py holds to every fingerprint input",
    # A BUILDER. It builds, loads and names the pinned extraction image the formal lanes run
    # in, from the dispatched extraction-image.yml and local_gate.sh stage 3; the lanes that
    # decide something run inside the image it produces.
    f"{ENTRY_ROOT}/extraction-image": "builds and names the pinned extraction image; the lanes that decide run inside it",
}


def entry_point_defects(
    population: set[str],
    unconditional: set[str],
    dispatched: set[str],
    exempt: dict[str, str],
    filtered_only: set[str] | None = None,
    dispatch_problem: str | None = None,
) -> list[str]:
    """Entry points the merge path does not reach, and exemptions that name nothing."""
    found: list[str] = []
    if dispatch_problem:
        found.append(
            f"{dispatch_problem}. Every lane's entry point is reached through that table, "
            f"so this gate cannot say which lanes run until it can be read."
        )
    filtered_only = filtered_only or set()
    for script in sorted(population - unconditional - dispatched - exempt.keys()):
        why = (
            "is named only by a `paths:`-filtered workflow, so it runs on the pull requests "
            "that touch those paths and on no others"
            if script in filtered_only
            else "is reached by no unconditional workflow and by no dispatcher that one reaches"
        )
        found.append(
            f"{script} {why}. It is an assurance-platform entry point — an executable file "
            f"under {ENTRY_ROOT}/ — so something is meant to run it. Name it in an "
            f"unconditional workflow, run it from a reached dispatcher, or add it to "
            f"EXEMPT_ENTRY with the reason it decides nothing."
        )
    found.extend(
        f"EXEMPT_ENTRY names {script}, which is not an assurance-platform entry point in "
        f"this tree. A dead exemption is a claim about nothing and hides the next one that "
        f"matters."
        for script in sorted(exempt.keys() - population)
    )
    return found


def command_position_paths(commands: list[Command]) -> set[str]:
    """Every repository path these commands run AS A PROGRAM.

    A path handed to an interpreter (`python3 x.py`, `bash x.sh`, `. x.sh`) is an
    ARGUMENT, and an argument needs no execute bit; demanding one would make the gate ask
    for a property the invocation does not use. A path at the head of a command segment is
    a program, and needs one; so does a `./`-qualified path handed to a program that runs
    it.
    """
    found: set[str] = set()
    for command in commands:
        for invocation in command.invocations():
            if invocation.interpreter is None and invocation.program.startswith(("scripts/", "tools/")):
                found.add(invocation.program)
            # A `./`-qualified path handed to another program is one that program runs:
            # `docker run … "$image" ./tools/verification/regenerate-lean`, `xargs ./x`.
            found |= {
                arg[2:]
                for arg in (a.strip("\"'") for a in invocation.args)
                if arg.startswith(("./scripts/", "./tools/"))
            }
    return found


def truncating_fetches(workflow: Workflow) -> list[str]:
    """Shallow fetches in a job whose checkout asked for the full history.

    Per job: the two facts are a `fetch-depth: 0` on one of the job's steps and a `--depth`
    fetch among its commands. Another job's shallow fetch does not truncate this job's
    clone.
    """
    return [
        command.text
        for job in workflow.jobs.values()
        if any(step.with_.get("fetch-depth") == "0" for step in job.steps)
        for command in job.commands()
        if SHALLOW_FETCH.search(command.text)
    ]


def not_executable(paths: set[str]) -> list[str]:
    """Those of `paths` that exist in the tree and are not executable.

    The FILESYSTEM bit, which is what a fresh clone and a CI checkout both get from the
    index — so a developer who ran `chmod +x` locally and never staged the mode change sees
    a green gate here and a red one in CI. A path that does not exist is not this gate's
    finding: the coverage half above already refuses a control nothing can run, and
    reporting a missing file as a permissions defect would send someone to the wrong fix.
    """
    import os

    return sorted(
        path
        for path in paths
        if (REPO / path).is_file() and not os.access(REPO / path, os.X_OK)
    )


def selftest() -> int:
    """A gate whose only evidence is that a clean tree passes has never been shown to fail."""
    cases = [
        (
            {"scripts/a.py"},
            set(),
            {},
            "runs only in scripts/local_gate.sh",
            "a control on no workflow",
        ),
        (
            {"scripts/a.py"},
            {"scripts/a.py"},
            {},
            None,
            "a control a workflow names",
        ),
        (
            {"scripts/a.py"},
            set(),
            {"scripts/a.py": "local by design"},
            None,
            "an exempt control",
        ),
        (
            set(),
            set(),
            {"scripts/gone.py": "stale"},
            "which scripts/local_gate.sh does not invoke",
            "an exemption naming nothing",
        ),
    ]
    for gated, covered, exempt, needle, label in cases:
        found = defects(gated, covered, exempt)
        if needle is None:
            if found:
                print(f"SELFTEST FAIL: refused {label}: {found}", file=sys.stderr)
                return 1
            continue
        if not any(needle in entry for entry in found):
            print(f"SELFTEST FAIL: accepted {label}", file=sys.stderr)
            return 1
    # The two rules added after the sweep, each with the case that motivated it.
    filtered = defects(
        {"scripts/a.py"}, set(), {}, filtered_only={"scripts/a.py"}
    )
    if not any("`paths:`-filtered workflow" in entry for entry in filtered):
        print("SELFTEST FAIL: accepted a control named only by a filtered workflow", file=sys.stderr)
        return 1
    if any("runs only in scripts/local_gate.sh" in entry for entry in filtered):
        print("SELFTEST FAIL: a filtered-only control reported as local-only", file=sys.stderr)
        return 1
    uncovered_suite = defects(
        set(), set(), {}, selftests={"tools/verification/test_x.py"}
    )
    if not any("assurance-platform self-test" in entry for entry in uncovered_suite):
        print("SELFTEST FAIL: accepted a self-test no unconditional workflow names", file=sys.stderr)
        return 1
    covered_suite = defects(
        set(),
        {"tools/verification/test_x.py"},
        {},
        selftests={"tools/verification/test_x.py"},
    )
    if covered_suite:
        print(f"SELFTEST FAIL: refused a covered self-test: {covered_suite}", file=sys.stderr)
        return 1
    # A filtered workflow must not count as coverage, and an unfiltered one must.
    for text, expect, why in [
        ("on:\n  pull_request:\n    branches: [main]\n", "every", "a pull_request trigger with no paths key"),
        ("on:\n  pull_request:\n    paths:\n      - 'src/**'\n", "filtered", "a paths key"),
        ("on:\n  push:\n    branches: [main]\n  workflow_dispatch:\n", None, "a workflow no pull request starts"),
        ("on:\n  push:\n    paths:\n      - 'src/**'\n  pull_request:\n", "every", "a filter on push only"),
    ]:
        if pull_request_reach(parse(text)) != expect:
            print(f"SELFTEST FAIL: {why} read as {pull_request_reach(parse(text))!r}", file=sys.stderr)
            return 1

    # The extractor is half the gate: a pattern that stopped matching would report an empty
    # scope as a clean tree, which is the failure this repository has already shipped once.
    if "tools/verification/verify" in scripts_in(shell_commands("python3 tools/verification/verify")):
        print("SELFTEST FAIL: the extractor matched an extensionless path", file=sys.stderr)
        return 1
    for text, expect in [
        ("true \\\n    && python3 scripts/module_size_gate.py \\\n    --x", "scripts/module_size_gate.py"),
        ("true \\\n    && ./scripts/verification_runner_preflight.sh \\\n    --x", "scripts/verification_runner_preflight.sh"),
        ("python3 tools/verification/test_views.py", "tools/verification/test_views.py"),
    ]:
        if expect not in scripts_in(shell_commands(text)):
            print(f"SELFTEST FAIL: the extractor missed {expect} in {text!r}", file=sys.stderr)
            return 1
    # COUNT INVOCATIONS, NOT MENTIONS. A script a comment explains, or a usage line names,
    # is not one a workflow runs, and reading either as coverage is a control enforced by
    # prose.
    for text, why in [
        ("# python3 scripts/a_gate.py is why this step exists\ntrue", "a comment"),
        ('echo "usage: python3 scripts/a_gate.py"', "a usage line"),
    ]:
        if scripts_in(shell_commands(text)):
            print(f"SELFTEST FAIL: {why} counted as an invocation", file=sys.stderr)
            return 1
    # The command-position extractor, which is the half that found an unstageable mode.
    # Both directions, because either mistake is silent: a pattern that matched an
    # interpreted path would demand an execute bit nothing uses, and one that missed a
    # program would report a control as runnable that cannot start.
    for text, expect, why in [
        ("true \\\n    && tools/verification/evidence-class-census --selftest", True, "a program after &&"),
        ("jobs:\n  a:\n    steps:\n      - run: tools/verification/verify-mutations\n", True, "a program as a run: step"),
        ("  scripts/run_gate.sh --selftest", True, "a program at the head of a line"),
        ("true \\\n    && python3 tools/verification/test_views.py", False, "an argument to python3"),
        ("    . scripts/lib/sat_replay_fleet.sh || exit 1", False, "a sourced shim"),
        ("jobs:\n  a:\n    steps:\n      - run: bash scripts/demo-local.sh\n", False, "an argument to bash"),
        ('docker run --rm "$image" \\\n  ./tools/verification/regenerate-lean', True, "a program another program runs"),
        ('image="$(python3 tools/verification/extraction-image load)"', False, "an argument to python3 inside a substitution"),
    ]:
        commands = parse(text).commands() if text.startswith("jobs:") else shell_commands(text)
        matched = bool(command_position_paths(commands))
        if matched is not expect:
            print(
                f"SELFTEST FAIL: command-position extractor {'missed' if expect else 'matched'} "
                f"{why}: {text!r}",
                file=sys.stderr,
            )
            return 1
    # And the verdict itself: a path that exists and is not executable must be reported,
    # while a missing path must not be — that is the coverage half's finding, and naming it
    # here would send someone to the wrong fix.
    if not not_executable({"scripts/local_gate.sh", "README.md"}) == ["README.md"]:
        print("SELFTEST FAIL: the executable check does not distinguish a non-executable file", file=sys.stderr)
        return 1
    if not_executable({"scripts/a-file-that-does-not-exist.sh"}):
        print("SELFTEST FAIL: a missing path was reported as a permissions defect", file=sys.stderr)
        return 1
    # The shallow-fetch rule, both directions. It exists because the defect it names was
    # introduced BY a new control and broke a different one: the fix and the breakage were
    # in the same commit, and nothing related them.
    for text, expect, why in [
        ("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          fetch-depth: 0\n      - run: git fetch --no-tags --depth=1 origin main\n",
         True, "a --depth fetch in a deep checkout"),
        ("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          fetch-depth: 0\n      - run: git fetch --no-tags origin main\n",
         False, "a full fetch in a deep checkout"),
        ("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n      - run: git fetch --depth=1 origin main\n",
         False, "a shallow fetch where no step asked for the whole graph"),
        ("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          fetch-depth: 0\n      - run: git fetch --shallow-since=2026-01-01 origin main\n",
         True, "the other shallowing form"),
        ("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          fetch-depth: 0\n"
         "  b:\n    steps:\n      - uses: actions/checkout@v7\n      - run: git fetch --depth=1 origin main\n",
         False, "a shallow fetch in a job that never took the whole graph, beside one that did"),
    ]:
        found = bool(truncating_fetches(parse(text)))
        if found is not expect:
            print(
                f"SELFTEST FAIL: shallow-fetch rule {'missed' if expect else 'flagged'} {why}",
                file=sys.stderr,
            )
            return 1
    # ---- the DEFINED population --------------------------------------------------------
    # Asserted against a real temporary tree rather than a stub, because the definition IS a
    # filesystem property: a stub would only prove this test and the code agree about a
    # sentence, and the sentence is the thing under test.
    import os
    import stat
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        directory = root / ENTRY_ROOT
        directory.mkdir(parents=True)
        (root / ".github" / "workflows").mkdir(parents=True)
        for name in ("a-control", "_a_module.py", "not-a-control"):
            (directory / name).write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        for name in ("a-control", "_a_module.py"):
            path = directory / name
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        found = entry_points(root)
        if found != {f"{ENTRY_ROOT}/a-control"}:
            print(f"SELFTEST FAIL: the population is {found!r}", file=sys.stderr)
            return 1
        # The EXECUTE BIT is the discriminator, not the name. Take it away and the same
        # filename leaves the population; that is what makes the census complete by
        # construction rather than by a convention someone has to remember.
        control = directory / "a-control"
        control.chmod(control.stat().st_mode & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH)
        if entry_points(root):
            print("SELFTEST FAIL: a non-executable file stayed in the population", file=sys.stderr)
            return 1
        control.chmod(control.stat().st_mode | stat.S_IXUSR)
        # A directory with no entry points must FAIL the caller, not read as agreement —
        # asserted through the same accessor the caller uses.
        if entry_points(root / "nowhere"):
            print("SELFTEST FAIL: a missing root produced a population", file=sys.stderr)
            return 1
        # And an unreached entry point is a defect.
        orphaned = entry_point_defects({f"{ENTRY_ROOT}/a-control"}, set(), set(), {})
        if not any("reached by no unconditional workflow" in d for d in orphaned):
            print(f"SELFTEST FAIL: an unreached entry point passed: {orphaned}", file=sys.stderr)
            return 1
        # Named by an unconditional workflow; dispatched by a reached dispatcher; exempt.
        for unconditional, dispatched, exempt, label in [
            ({f"{ENTRY_ROOT}/a-control"}, set(), {}, "named by an unconditional workflow"),
            (set(), {f"{ENTRY_ROOT}/a-control"}, {}, "dispatched by verify's LANES"),
            (set(), set(), {f"{ENTRY_ROOT}/a-control": "decides nothing"}, "exempt with a reason"),
        ]:
            if entry_point_defects({f"{ENTRY_ROOT}/a-control"}, unconditional, dispatched, exempt):
                print(f"SELFTEST FAIL: refused an entry point {label}", file=sys.stderr)
                return 1
        # Filtered-only is its own message: the remedy differs.
        filtered = entry_point_defects(
            {f"{ENTRY_ROOT}/a-control"}, set(), set(), {}, {f"{ENTRY_ROOT}/a-control"}
        )
        if not any("`paths:`-filtered" in d for d in filtered):
            print(f"SELFTEST FAIL: a filtered-only entry point read as unreached: {filtered}", file=sys.stderr)
            return 1
        # A dead exemption is a claim about nothing.
        dead = entry_point_defects(set(), set(), set(), {f"{ENTRY_ROOT}/gone": "removed"})
        if not any("dead exemption" in d for d in dead):
            print(f"SELFTEST FAIL: a dead entry exemption passed: {dead}", file=sys.stderr)
            return 1
        # An unreadable dispatcher is ONE defect naming its cause, never nine orphans.
        _, problem = dispatched_entry_points(root)
        if problem is None:
            print("SELFTEST FAIL: a tree with no verify reported a readable LANES table", file=sys.stderr)
            return 1
        if not entry_point_defects(set(), set(), set(), {}, None, problem):
            print("SELFTEST FAIL: an unreadable dispatcher produced no defect", file=sys.stderr)
            return 1

    # The real dispatcher must be readable HERE, or the check above proves only that a
    # missing file is missing.
    lanes, problem = dispatched_entry_points(REPO)
    if problem is not None or not lanes:
        print(f"SELFTEST FAIL: this tree's verify LANES table could not be read: {problem}", file=sys.stderr)
        return 1
    # The coverage matcher must see an EXTENSIONLESS entry point, which is the shape
    # `scripts_in` is structurally unable to match and the reason this half exists.
    if names_in(shell_commands("./tools/verification/verify-tests")) != {f"{ENTRY_ROOT}/verify-tests"}:
        print("SELFTEST FAIL: the coverage matcher cannot see an extensionless entry point", file=sys.stderr)
        return 1

    print("merge_path_gate selftest: OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    gated = invoked_by(LOCAL_GATE)
    if not gated:
        # An empty scope is the gate measuring nothing while printing OK.
        print(
            f"FAIL: merge-path gate found no script invocations in {LOCAL_GATE}. "
            f"The extractor has stopped matching.",
            file=sys.stderr,
        )
        return 1
    covered, filtered_only = workflow_coverage()
    selftests = {
        path.relative_to(REPO).as_posix() for path in REPO.glob(SELFTEST_GLOB)
    }
    if not selftests:
        print(
            f"FAIL: no assurance-platform self-test matched {SELFTEST_GLOB}. An empty "
            f"scope is the gate measuring nothing while printing OK.",
            file=sys.stderr,
        )
        return 1
    runnable = command_position_paths(shell_commands(LOCAL_GATE.read_text(encoding="utf-8")))
    truncating: list[str] = []
    for workflow in workflows(REPO):
        runnable |= command_position_paths(workflow.commands())
        truncating += [
            f"{Path(workflow.path).name}: `{line}` SHALLOWS a clone its job took at "
            f"`fetch-depth: 0`. A shallow fetch truncates the object graph rather than "
            f"extending it, so every later step that asks an ancestry question measures a "
            f"history that is no longer there. Drop the depth flag, or read the ref the "
            f"deep checkout already provides."
            for line in truncating_fetches(workflow)
        ]
    found = list(truncating)
    found += [
        f"{path} is invoked as a program by local_gate.sh or a workflow and is NOT "
        f"executable. A control that cannot start is not enforced — this is `Permission "
        f"denied`, stage 1, on every fresh checkout. Stage the mode: "
        f"`git update-index --chmod=+x {path}`."
        for path in not_executable(runnable)
    ]
    found += defects(gated, covered, EXEMPT, filtered_only, selftests)

    # THE DEFINED POPULATION. The two sets above are places someone thought to look; this
    # one is every executable file under tools/verification/, which is what makes a file an
    # entry point at all.
    population = entry_points(REPO)
    if not population:
        print(
            f"FAIL: no assurance-platform entry point found under {ENTRY_ROOT}/. The "
            f"population is defined by the execute bit, and an empty one means the "
            f"definition stopped matching — not that the platform has no controls.",
            file=sys.stderr,
        )
        return 1
    entry_unconditional, entry_filtered = workflow_entry_coverage(REPO)
    dispatched, dispatch_problem = dispatched_entry_points(REPO)
    found += entry_point_defects(
        population,
        entry_unconditional,
        dispatched,
        EXEMPT_ENTRY,
        entry_filtered,
        dispatch_problem,
    )

    for defect in found:
        print(f"FAIL: {defect}", file=sys.stderr)
    if found:
        return 1
    exemptions = ", ".join(f"{name} ({why})" for name, why in sorted(EXEMPT.items()))
    print(
        f"merge-path gate: OK — {len(gated)} script(s) invoked by local_gate.sh and "
        f"{len(selftests)} platform self-test(s), all named by an UNCONDITIONAL workflow "
        f"except: {exemptions}; {len(runnable)} path(s) run as programs, all executable"
    )
    entry_exemptions = ", ".join(
        f"{name.rsplit('/', 1)[-1]} ({why})" for name, why in sorted(EXEMPT_ENTRY.items())
    )
    print(
        f"merge-path gate: OK — {len(population)} assurance-platform entry point(s) under "
        f"{ENTRY_ROOT}/, {len(entry_unconditional & population)} named by an unconditional "
        f"workflow and {len(dispatched & population)} dispatched by verify's LANES table; "
        f"exempt: {entry_exemptions}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
