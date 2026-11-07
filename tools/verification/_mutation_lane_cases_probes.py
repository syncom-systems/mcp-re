# SPDX-License-Identifier: Apache-2.0
"""Compound probes, the battery's seam, and the matrix preparation refusals.

Cases for `test_mutation_lane.py`, which runs them.
"""

from __future__ import annotations

import inspect
import tempfile
from pathlib import Path

from _mutation_lane_support import lane


def test_a_compound_probe_applies_and_reverts_every_site_together():
    """Defence in depth needs the COMPLETE carrying set removed, or it measures nothing.

    Where several sites each enforce the whole proposition, weakening one leaves the others
    holding the property and the lane reports the conjunct as unprotected -- which is false,
    and is the one verdict this lane must never reach dishonestly.

    All-or-nothing, and reverted whole: a partial application would leave a surviving carrier,
    and a partial revert would leave the working tree's COPY weakened for every probe after it.
    """
    compound = [probe for probe in lane.load_probes() if probe.get("also")]
    assert compound, "no probe uses the compound form; this control has nothing to measure"

    import _mutation

    body = inspect.getsource(lane.apply)
    resolver = inspect.getsource(_mutation.weaken)
    # The sites are validated BEFORE any file is written: every site resolves in `weaken`,
    # which writes nothing, and `apply` writes only what it returned.
    assert body.index("weaken(") < body.index("write_text"), body
    assert "STALE" in resolver and "write_text" not in resolver, resolver
    # And each further weakening is applied to the text as already weakened, so two sites in
    # ONE file compound instead of the last one winning.
    assert "weakened[path].count(anchor)" in resolver, resolver

    with tempfile.TemporaryDirectory() as raw:
        tree = Path(raw)
        (tree / "src").mkdir()
        (tree / "src/one.txt").write_text("alpha\nbeta\n")
        probe = {
            "path": "src/one.txt",
            "anchor": "alpha\n",
            "weakening": "ALPHA\n",
            "also": [{"path": "src/one.txt", "anchor": "beta\n", "weakening": "BETA\n"}],
        }
        originals = lane.apply(tree, probe, "probe TEST")
        assert (tree / "src/one.txt").read_text() == "ALPHA\nBETA\n", "both sites"
        for path, text in originals.items():
            (tree / path).write_text(text)
        assert (tree / "src/one.txt").read_text() == "alpha\nbeta\n", "reverted whole"


def test_a_compound_probe_may_not_name_one_site_twice():
    """Weakening one site twice weakens one site.

    A probe that did would report a compound falsifier over a carrying set it never removed --
    the same dishonest green as a single-anchor probe against defence in depth, wearing the
    mechanism built to refuse it.
    """
    for probe in lane.load_probes():
        sites = [(probe["path"], probe["anchor"])] + [
            (also["path"], also["anchor"]) for also in probe.get("also", [])
        ]
        assert len(set(sites)) == len(sites), probe["id"]


def test_the_battery_runs_through_the_same_seam_as_the_test_lane():
    """A control green in the test lane and unrunnable in this one would be two answers
    about one declared symbol. Both resolve the command and the report through
    `_ecosystems`, so there is one answer per ecosystem rather than one per tool."""
    body = inspect.getsource(lane.run_battery)
    assert "test_argv(eco," in body
    assert "parse_results(eco," in body


def test_an_sdk_battery_runs_inside_its_own_project():
    """pytest and vitest selections are relative to the project that holds their
    configuration; Bazel resolves a label from the workspace root. Running a pytest
    selection from the tree root would select nothing and report a green battery."""
    body = inspect.getsource(lane.run_battery)
    assert "cwd = tree / package" in body
    assert "cwd = tree\n" in body or "cwd = tree" in body


def test_an_absent_matrix_and_a_stale_artefact_are_different_refusals():
    """`prepare_scratch` returns a typed cause, and only one of them is skippable.

    An absent SDK matrix is an ENVIRONMENT fact -- the lean lane is reported the same way
    outside the extraction image. A probe that would weaken a source the carried binary was
    compiled from is a PROBE DEFECT: the battery would run old native code against a new
    declaration, and no flag may wave that through. Sharing one signal would make
    `--skip-unprepared` silently skip the defect too.
    """
    assert lane.UNPREPARED != lane.STALE
    body = inspect.getsource(lane.main)
    assert "cause == lane.UNPREPARED" in body or "cause == UNPREPARED" in body
    # The skip is conditioned on BOTH the cause and the flag, never on the flag alone.
    assert "args.skip_unprepared" in body
    guard = body[body.index("args.skip_unprepared") - 120 : body.index("args.skip_unprepared")]
    assert "UNPREPARED" in guard


def test_a_needed_artefact_is_looked_for_where_the_preparation_leaves_it():
    """The Python native module is looked for under the name the Bazel wheel gives it.

    `prepare_python_matrix.sh` -- the form the verification workflow runs, and the one that
    pins an environment per supported interpreter -- installs the Bazel-built WHEEL, whose
    extension is `mcp_re_sdk/_core.so`, so the tree has no `.so` at all. A lane that looked
    for another spelling reported a correctly prepared runner as an unbuilt environment and
    failed every Python probe on it; that happened on the first change to a Python unit's
    inputs after the migration, because nothing exercised it before.

    Asked over a CONSTRUCTED workspace rather than this one: the fast job that runs these
    self-tests builds no SDK matrix at all, so a control needing the module present would
    fail there for the environment rather than for the rule.
    """
    wanted = "python/mcp_re_sdk/_core.so"
    candidates = lane._SCRATCH_NEEDS[lane.PYTHON][wanted]
    assert all("site-packages" in spelling for spelling in candidates), candidates

    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        assert lane._first_present(root, wanted, candidates) == [], "an empty workspace"

        # The installed spelling ALONE resolves -- the shape a prepared runner has.
        installed = root / ".venv-cp314/lib/python3.14/site-packages/mcp_re_sdk"
        installed.mkdir(parents=True)
        (installed / "_core.so").write_bytes(b"")
        from_wheel = lane._first_present(root, wanted, candidates)
        assert [relative for _s, relative in from_wheel] == [wanted], from_wheel


def test_an_unavailable_probe_is_named_in_the_verdict_line():
    """A skipped probe that did not appear in the verdict would let this job's green be
    read as "every registered probe was applied", which is the false green the whole lane
    exists to refuse -- one level up."""
    body = inspect.getsource(lane.main)
    assert "UNAVAILABLE in this environment" in body
    assert "unavailable.append" in body


def test_the_probe_job_prepares_the_matrix_it_measures_in():
    """The SDK shards prepare their matrix and the lane then runs WITHOUT the skip flag.

    A shard that selects SDK probes without preparing the matrix they run in reads every one
    of them UNAVAILABLE, and a shard that selected only those has measured nothing: red, for
    a lane that was supposed to have a prepared environment. So the workflow prepares each
    matrix with the same script the complete run uses, in a step the lane cannot precede,
    and passes no flag that would turn an absent environment back into a skipped probe.
    """
    workflow = (lane.REPO_ROOT / ".github/workflows/mutation-probe.yml").read_text()
    assert "--skip-unprepared" not in workflow
    assert "Apply every registered probe" not in workflow
    prepare_python = workflow.index("./scripts/prepare_python_matrix.sh")
    prepare_node = workflow.index("./scripts/prepare_node_matrix.sh")
    applied = workflow.index("tools/verification/verify-mutations ${{ matrix.args }}")
    assert prepare_python < applied and prepare_node < applied
    assert "if: matrix.prepare == 'python'" in workflow
    assert "if: matrix.prepare == 'typescript'" in workflow


def test_skipping_every_probe_is_not_a_pass():
    """`--skip-unprepared` reintroduced the exact shape this lane set is ratified against:
    every probe skipped, nothing weakened, nothing observed, and a green verdict. Measured
    by hiding `node_modules` and running the flag -- it printed `PASS -- 0 probe(s)`."""
    body = inspect.getsource(lane.main)
    assert "measured == 0" in body
    assert "VERDICT: UNAVAILABLE" in body
    # And the pass branch is reached only after that check.
    assert body.index("measured == 0") < body.index("verify-mutations: PASS")


def test_the_refusal_names_a_script_that_exists():
    """The message derived the filename from the ecosystem name, so TypeScript's refusal
    told a reader to run `prepare_typescript_matrix.sh`. There is no such file -- the Node
    matrix is built by `prepare_node_matrix.sh` -- and a confident pointer to a file that
    does not exist is worse than none."""
    for eco, script in lane._MATRIX_SCRIPT.items():
        assert (lane.REPO_ROOT / script).is_file(), (eco.name, script)
