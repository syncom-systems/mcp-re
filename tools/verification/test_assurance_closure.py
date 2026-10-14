# SPDX-License-Identifier: Apache-2.0
"""Assurance closure — which runs may close, and what closing requires (#1172).

The single claim:

    Repository assurance closes only from a complete run's PASS, through attestations
    `attest` issued at the exact measured fingerprints, when every active theorem is
    REVIEW_CURRENT, EVIDENCE_ESTABLISHED and CURRENTLY_VERIFIED and every root is complete.

Two halves. The command's own decision (`evaluate`, `run_refusals`, `close`) is driven with
synthetic `review --json` output and a stub runner, so each refusal is pinned without a
17-second fingerprint pass. The issuance half is `attest`'s authority, so it is asked of
`_evidence.decide_issuance` directly rather than restated here. The workflow half reads
`verification.yml` through `scripts/workflow_reader.py`.

Run: python3 tools/verification/test_assurance_closure.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "scripts"))

from _evidence import EvidenceRecord, decide_issuance, write_bundle  # noqa: E402
from _load_tool import load_tool  # noqa: E402
import workflow_reader  # noqa: E402

closure = load_tool("assurance-closure", "assurance_closure")
WORKFLOW = REPO / ".github" / "workflows" / "verification.yml"
TOOL = "tools/verification/assurance-closure"

COMPLETE_RUN = {"id": "1", "attempt": "1", "event": "workflow_dispatch", "evidence_commit": "c"}
TARGET = {"commit": "c", "tree": "t"}


def theorem(**kwargs):
    return closure._theorem(**kwargs)


def review(theorems, roots=("THM-A",), blocking=None):
    return closure._review(theorems, roots, blocking)


def bundle(directory: Path, aggregate="PASS", scope=None) -> Path:
    write_bundle(directory, aggregate, {"test": aggregate}, "r", scope)
    return directory


class Runner:
    """Records each authority the command calls and answers as configured."""

    def __init__(self, attest=(0, "", ""), review_doc=None):
        self.calls: list[list[str]] = []
        self.attest = attest
        self.review_doc = review_doc

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[0].endswith("/attest"):
            store = Path(argv[argv.index("--store") + 1])
            if self.attest[0] == 0:
                store.mkdir(parents=True, exist_ok=True)
                (store / "u.json").write_text("{}", encoding="utf-8")
            return self.attest
        return 0, json.dumps(self.review_doc), ""

    def tools(self):
        return [Path(call[0]).name for call in self.calls]


def run_close(evidence_bundle=None, runner=None, run=COMPLETE_RUN, depends_on=None):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        evidence = tmp / "evidence"
        evidence.mkdir()
        if evidence_bundle is not None:
            bundle(evidence, **evidence_bundle)
        out = tmp / "out"
        out.mkdir()
        record = closure.close(evidence, out, run, TARGET, runner, depends_on or {})
        return record, evidence, out


COMPLETE_REVIEW = review({"THM-A": theorem(), "THM-B": theorem()})


# --- a scoped run cannot close, and cannot issue ------------------------------


def test_a_scoped_bundle_is_refused_before_anything_is_attested():
    runner = Runner(review_doc=COMPLETE_REVIEW)
    record, _, _ = run_close({"aggregate": "INCOMPLETE", "scope": ("u",)}, runner)
    assert record["verdict"] == "FAIL"
    assert any("scoped" in r for r in record["refusals"])
    assert runner.calls == []


def test_a_pull_request_or_push_run_is_refused_even_at_full_reach():
    """A change that expanded to every unit composes an unscoped PASS bundle. It is still
    not a run anyone asked to be complete."""
    for event in ("pull_request", "push"):
        runner = Runner(review_doc=COMPLETE_REVIEW)
        record, _, _ = run_close({}, runner, run={**COMPLETE_RUN, "event": event})
        assert record["verdict"] == "FAIL", event
        assert runner.calls == [], event


def test_a_run_without_a_composed_verdict_is_refused():
    runner = Runner(review_doc=COMPLETE_REVIEW)
    record, _, _ = run_close(None, runner)
    assert record["verdict"] == "FAIL" and runner.calls == []


def test_a_failed_aggregate_is_refused():
    runner = Runner(review_doc=COMPLETE_REVIEW)
    record, _, _ = run_close({"aggregate": "FAIL"}, runner)
    assert record["verdict"] == "FAIL" and runner.calls == []


def test_the_issuer_itself_refuses_a_scoped_runs_evidence():
    """The second wall: `attest` reads a scoped run's INCOMPLETE aggregate and refuses PASS
    issuance whatever the records say."""
    got = decide_issuance(
        [{"id": "u", "evidence": ["test://t"]}],
        [],
        {"u": {"fingerprint": "sha256:X"}},
        {"test": {"u": EvidenceRecord(unit_id="u", lane="test", result="pass", fingerprint="sha256:X")}},
        "INCOMPLETE",
    )
    assert got["u"][0] == "REFUSE"


# --- a complete PASS issues at the exact fingerprints -------------------------


def test_a_complete_pass_attests_the_runs_own_evidence_into_a_fresh_store():
    runner = Runner(review_doc=COMPLETE_REVIEW)
    record, evidence, out = run_close({}, runner)
    assert runner.tools() == ["attest", "review"]
    attest = runner.calls[0]
    assert attest[attest.index("--evidence") + 1] == str(evidence)
    assert attest[attest.index("--store") + 1] == str(out / "attestations")
    review_call = runner.calls[1]
    assert review_call[review_call.index("--attestations") + 1] == str(out / "attestations")
    assert record["attested"] == 1
    assert record["verdict"] == "PASS"


def test_the_issuer_issues_a_complete_pass_at_the_measured_fingerprint():
    got = decide_issuance(
        [{"id": "u", "evidence": ["test://t"]}],
        [],
        {"u": {"fingerprint": "sha256:X"}},
        {"test": {"u": EvidenceRecord(unit_id="u", lane="test", result="pass", fingerprint="sha256:X")}},
        "PASS",
    )
    assert got["u"][0] == "ISSUE_PASS"


# --- a fingerprint that moved after measurement refuses -----------------------


def test_the_issuer_refuses_evidence_measured_at_another_fingerprint():
    got = decide_issuance(
        [{"id": "u", "evidence": ["test://t"]}],
        [],
        {"u": {"fingerprint": "sha256:Y"}},
        {"test": {"u": EvidenceRecord(unit_id="u", lane="test", result="pass", fingerprint="sha256:X")}},
        "PASS",
    )
    assert got["u"][0] == "REFUSE"
    assert "do not match current fingerprint" in got["u"][2]


def test_an_attestation_refusal_fails_closure_and_names_the_unit():
    refused = "  REFUSED  u   the test record was measured at sha256:X but the unit now ..."
    runner = Runner(attest=(1, refused + "\n", "FAIL: refused to issue 1 attestation(s)."), review_doc=COMPLETE_REVIEW)
    record, _, _ = run_close({}, runner)
    assert record["verdict"] == "FAIL"
    assert runner.tools() == ["attest"], "nothing is evaluated over a refused issuance"
    assert any(r.startswith("REFUSED  u") for r in record["refusals"])


# --- the three axes and the roots ---------------------------------------------


def test_current_reviews_over_complete_evidence_close():
    got = closure.evaluate(COMPLETE_REVIEW, {})
    assert got["verdict"] == "PASS"
    assert got["counts"]["review_current"] == got["counts"]["active"] == 2


def test_a_stale_semantic_review_fails_closure_over_complete_evidence():
    got = closure.evaluate(review({"THM-A": theorem(), "THM-B": theorem(review=False)}), {})
    assert got["verdict"] == "FAIL"
    assert got["counts"]["evidence_established"] == 2
    [row] = got["blockers"]["review"]
    assert row["theorem"] == "THM-B" and row["state"] == "STALE_SEMANTICS"
    assert "unit://u" in row["reason"]


def test_an_unreviewed_assumption_is_named_with_the_theorems_it_is_a_premise_of():
    premises = {"ASM-1": ["STALE_INPUT", "changed since review: assumption_entry"]}
    stale = theorem(review=False, premises=premises)
    stale["review"] = ["PREMISE_UNREVIEWED", "ASM-1 STALE_INPUT"]
    got = closure.evaluate(review({"THM-A": theorem(), "THM-B": stale}), {})
    assert got["verdict"] == "FAIL"
    assert got["blockers"]["assumptions"] == [
        {"assumption": "ASM-1", "state": "STALE_INPUT", "reason": "changed since review: assumption_entry", "theorems": ["THM-B"]}
    ]


def test_each_axis_is_required_on_its_own():
    """CURRENTLY_VERIFIED implies the other two in `review`'s derivation; closure still
    requires all three, so it does not rest on that implication holding."""
    for axis in closure.AXES:
        inconsistent = theorem()
        inconsistent[axis] = False
        got = closure.evaluate(review({"THM-A": theorem(), "THM-B": inconsistent}), {})
        assert got["verdict"] == "FAIL", axis


def test_a_non_fresh_unit_is_named_with_the_theorems_it_supports():
    got = closure.evaluate(review({"THM-A": theorem(), "THM-B": theorem(evidence=False)}), {})
    assert got["verdict"] == "FAIL"
    assert got["blockers"]["units"] == [{"unit": "u", "state": "UNKNOWN", "theorems": ["THM-B"]}]


def test_a_dependency_stale_theorem_is_not_currently_verified_and_fails_closure():
    """Both local axes hold, so only the dependency explains it — and the report says so."""
    got = closure.evaluate(
        review({"THM-A": theorem(verified=False), "THM-B": theorem(review=False)}),
        {"THM-A": ["THM-B"]},
    )
    assert got["verdict"] == "FAIL"
    assert got["counts"]["currently_verified"] == 0
    assert got["blockers"]["dependency_only"] == [{"theorem": "THM-A", "blocked_by": ["THM-B"]}]


def test_an_incomplete_root_fails_closure_and_names_its_blocker():
    blocking = {"THM-A": [{"theorem": "THM-A", "cause": "GAP: no support closure"}]}
    got = closure.evaluate(review({"THM-A": theorem(), "THM-B": theorem()}, blocking=blocking), {})
    assert got["verdict"] == "FAIL"
    assert got["blockers"]["roots"] == [{"root": "THM-A", "blocked_by": blocking["THM-A"]}]


def test_no_declared_root_does_not_close():
    got = closure.evaluate(review({"THM-A": theorem()}, roots=()), {})
    assert got["verdict"] == "FAIL" and got["root_verdict"] == "UNDECLARED"


def test_a_deprecated_theorem_leaves_the_denominator_and_an_empty_registry_does_not_close():
    got = closure.evaluate(
        review({"THM-A": theorem(), "THM-B": theorem(evidence=False, deprecated=True)}), {}
    )
    assert got["verdict"] == "PASS" and got["counts"]["active"] == 1
    assert got["counts"]["deprecated"] == 1
    assert closure.evaluate(review({}, roots=("THM-A",)), {})["verdict"] == "FAIL"


def test_exactly_one_verdict_line_is_printed():
    record = {"run": COMPLETE_RUN, "target": TARGET, **closure.evaluate(COMPLETE_REVIEW, {})}
    lines = closure.report(record).splitlines()
    assert [line for line in lines if line.startswith(closure.VERDICT_PREFIX)] == [
        "ASSURANCE CLOSURE: PASS"
    ]


def test_a_used_output_directory_is_refused():
    """`attest` leaves a refused unit's previous attestation alone, so a store that already
    held one could let it stand in for a unit this run did not establish."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out"
        (out / "attestations").mkdir(parents=True)
        (out / "attestations" / "u.json").write_text("{}", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(REPO / TOOL), "--evidence", tmp, "--event", "workflow_dispatch", "--out", str(out)],
            capture_output=True, text=True, check=False,
        )
        assert proc.returncode == 1
        assert "not empty" in proc.stdout
        assert proc.stdout.strip().splitlines()[-1] == "ASSURANCE CLOSURE: FAIL"


# --- the workflow calls the authority and decides nothing itself --------------


def _workflow():
    text = WORKFLOW.read_text(encoding="utf-8")
    return text, workflow_reader.parse(text, str(WORKFLOW)), workflow_reader.parse_yaml(text)


def _runs(job):
    return [step.run.value for step in job.steps if step.run is not None]


def _invoked(job) -> set[str]:
    found = set()
    for body in _runs(job):
        for command in workflow_reader.shell_commands(body):
            for invocation in command.invocations():
                found.add(str(invocation.program).removeprefix("./"))
    return found


def test_the_closure_job_runs_only_after_a_successful_aggregate_of_a_complete_run():
    _, _, top = _workflow()
    job = top.get("jobs").get("assurance-closure")
    condition = job.get("if").value
    assert "needs.aggregate.result == 'success'" in condition
    assert "needs.scope.outputs.complete == 'true'" in condition
    assert [n.value for n in job.get("needs").items] == ["scope", "aggregate"]


def test_scope_sets_complete_true_only_for_dispatch_and_schedule():
    _, wf, top = _workflow()
    outputs = top.get("jobs").get("scope").get("outputs")
    assert outputs.get("complete").value == "${{ steps.scope.outputs.complete }}"
    [body] = [b for b in _runs(wf.jobs["scope"]) if "complete=" in b]
    true_lines = [line for line in body.splitlines() if 'echo "complete=true"' in line]
    assert len(true_lines) == 1
    arm = body[: body.index(true_lines[0])].rsplit("\n", 3)
    assert "schedule|workflow_dispatch)" in "\n".join(arm[-3:])
    # The complete arm exits before the scoped path, which writes false.
    after = body[body.index(true_lines[0]):]
    assert "exit 0" in after.split("\n", 2)[1]
    assert 'echo "complete=false" >> "$GITHUB_OUTPUT"' in after
    assert set(closure.COMPLETE_EVENTS) == {"workflow_dispatch", "schedule"}


def test_the_closure_job_calls_the_authority_and_runs_no_lane():
    _, wf, _ = _workflow()
    invoked = _invoked(wf.jobs["assurance-closure"])
    assert invoked == {TOOL}, invoked


def test_no_workflow_issues_attestations_or_judges_theorems_itself():
    """`attest` and `review` are reached only through the closure authority, and no run
    body spells an axis — a workflow that counted them would be a second semantics."""
    axis_words = ("REVIEW_CURRENT", "EVIDENCE_ESTABLISHED", "CURRENTLY_VERIFIED", "currently_verified", "review_current", "evidence_established")
    for path in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        wf = workflow_reader.read(path)
        for key, job in wf.jobs.items():
            invoked = _invoked(job)
            assert "tools/verification/attest" not in invoked, (path.name, key)
            assert "tools/verification/review" not in invoked, (path.name, key)
            for body in _runs(job):
                assert not any(word in body for word in axis_words), (path.name, key)


def test_the_earlier_run_entry_point_is_dispatch_only_and_calls_the_authority():
    """The additional path: re-evaluate a finished run. Never a pull-request or push trigger."""
    wf = workflow_reader.read(REPO / ".github" / "workflows" / "assurance-closure.yml")
    assert set(wf.triggers) == {"workflow_dispatch"}
    assert {key: _invoked(job) for key, job in wf.jobs.items()} == {"closure": {TOOL}}
    [body] = _runs(wf.jobs["closure"])
    assert "--run" in body


def test_the_closure_record_is_uploaded_by_run_id_and_attempt():
    _, wf, _ = _workflow()
    uploads = [s for s in wf.jobs["assurance-closure"].steps if (s.uses or "").startswith("actions/upload-artifact")]
    assert len(uploads) == 1
    assert uploads[0].with_["name"] == "assurance-closure-${{ github.run_id }}-${{ github.run_attempt }}"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name} {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
