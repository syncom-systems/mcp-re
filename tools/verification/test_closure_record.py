# SPDX-License-Identifier: Apache-2.0
"""The committed closure record — negative controls for #1173 (MCPRE-220).

The single claim:

    A closure record states that its target tree closed at the identities it lists. Any
    moved identity is named; the record cannot stand in for an attestation; and it stays
    true of its target after `main` advances.

Run: python3 tools/verification/test_closure_record.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import _closure_record as cr  # noqa: E402
from _graph import evaluate, load_attestations  # noqa: E402


def review(units=None, theorems=None, policy="p", ledger="sha256:ledger"):
    units = units or {"a": "sha256:a", "b": "sha256:b"}
    theorems = theorems or {
        "THM-A": {"fingerprint": "sha256:ta", "review_digest": "sha256:ra"},
        "THM-B": {"fingerprint": "sha256:tb", "review_digest": "sha256:rb"},
    }
    return {
        "theorems": {tid: {"deprecated": False} for tid in theorems},
        "root_completeness": {"roots": ["THM-A"], "verdict": "COMPLETE"},
        "identities": {
            "policy_revision": policy,
            "review_ledger": ledger,
            "units": units,
            "theorems": theorems,
        },
    }


def closure(commit="c0", tree="t0", active=2):
    return {
        "verdict": "PASS",
        "target": {"commit": commit, "tree": tree},
        "run": {"id": 38513625401, "attempt": 1, "event": "workflow_dispatch", "evidence_commit": "e"},
        "counts": {
            "active": active,
            "review_current": active,
            "evidence_established": active,
            "currently_verified": active,
            "roots": 1,
            "roots_established": 1,
        },
    }


RECORD = cr.build(closure(), review())


def copy(record):
    return json.loads(json.dumps(record))


def moved(current_review, tree: str | None = "t0"):
    return cr.compare(RECORD, cr.current_identities(current_review, tree))


# --- the happy path, so the refusals below mean something ---------------------


def test_a_built_record_agrees_with_itself_and_with_an_identical_tree():
    assert cr.problems(RECORD) == []
    assert moved(review()) == []


def test_the_serialized_record_reads_back_identically():
    assert json.loads(cr.dumps(RECORD)) == RECORD


def test_the_record_keeps_every_identity_not_only_digests():
    assert [row["unit"] for row in RECORD["units"]] == ["a", "b"]
    assert RECORD["theorems"][1] == {"theorem": "THM-B", "fingerprint": "sha256:tb", "review_digest": "sha256:rb"}


def test_only_a_pass_is_recorded():
    failed = closure()
    failed["verdict"] = "FAIL"
    try:
        cr.build(failed, review())
    except ValueError:
        return
    raise AssertionError("a FAIL was recorded")


# --- one moved identity is named -----------------------------------------------


def test_one_changed_unit_fingerprint_breaks_the_comparison_and_is_named():
    got = moved(review(units={"a": "sha256:a", "b": "sha256:B"}))
    assert got == ["unit://b fingerprint: sha256:b -> sha256:B"]


def test_one_edited_unit_fingerprint_in_the_record_breaks_its_digest():
    tampered = copy(RECORD)
    tampered["units"][0]["fingerprint"] = "sha256:x"
    assert any("units_digest" in p for p in cr.problems(tampered))


def test_a_changed_theorem_fingerprint_or_review_digest_breaks_the_comparison():
    fp = review(theorems={
        "THM-A": {"fingerprint": "sha256:TA", "review_digest": "sha256:ra"},
        "THM-B": {"fingerprint": "sha256:tb", "review_digest": "sha256:rb"},
    })
    assert moved(fp) == ["THM-A fingerprint: sha256:ta -> sha256:TA"]
    rd = review(theorems={
        "THM-A": {"fingerprint": "sha256:ta", "review_digest": "sha256:ra"},
        "THM-B": {"fingerprint": "sha256:tb", "review_digest": "sha256:RB"},
    })
    assert moved(rd) == ["THM-B review_digest: sha256:rb -> sha256:RB"]
    tampered = copy(RECORD)
    tampered["theorems"][1]["review_digest"] = "sha256:x"
    assert any("theorems_digest" in p for p in cr.problems(tampered))


def test_a_changed_policy_or_review_ledger_breaks_the_comparison():
    assert moved(review(policy="p2")) == ["policy_revision: p -> p2"]
    assert moved(review(ledger="sha256:other")) == ["review_ledger: sha256:ledger -> sha256:other"]


def test_a_unit_added_or_removed_is_named():
    got = moved(review(units={"a": "sha256:a"}))
    assert got == ["unit://b fingerprint: absent from the compared tree"]


def test_a_changed_target_tree_breaks_the_comparison():
    assert moved(review(), tree="t1") == ["tree: t0 -> t1"]
    assert moved(review(), tree=None) == ["tree: t0 -> None"]


def test_a_record_claiming_less_than_closure_is_refused():
    short = copy(RECORD)
    short["counts"]["review_current"] = 1
    assert any("review_current" in p for p in cr.problems(short))


# --- the record is not an attestation -----------------------------------------


def test_the_record_cannot_be_loaded_as_an_attestation():
    with tempfile.TemporaryDirectory() as tmp:
        store = Path(tmp)
        (store / "a.json").write_text(cr.dumps(RECORD), encoding="utf-8")
        (store / "c0.json").write_text(cr.dumps(RECORD), encoding="utf-8")
        assert load_attestations(store) == {}
        current = {uid: {"fingerprint": fp, "components": {}} for uid, fp in review()["identities"]["units"].items()}
        units = [{"id": uid, "evidence": ["test://t"]} for uid in current]
        states = evaluate(units, [], current, load_attestations(store))["states"]
        assert all(state != "FRESH" for state, _ in states.values()), states


def test_no_freshness_reader_looks_in_the_closures_directory():
    for path in sorted(HERE.glob("*")):
        if path.name in {"_closure_record.py", "closure-record", "test_closure_record.py", "assurance-closure", "test_assurance_closure.py", "README.md"} or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert not re.search(r"""closures/|["']closures["']|(import|from) _closure_record\b""", text), path.name


# --- a historical record stays true of its target ------------------------------


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()


def test_a_historical_record_stays_valid_after_main_advances_and_a_wrong_tree_does_not():
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        env = ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
        _git(repo, "init", "-q")
        (repo / "f").write_text("one", encoding="utf-8")
        _git(repo, "add", "f")
        _git(repo, *env, "commit", "-qm", "target")
        target, tree = _git(repo, "rev-parse", "HEAD"), _git(repo, "rev-parse", "HEAD^{tree}")
        (repo / "f").write_text("two", encoding="utf-8")
        _git(repo, *env, "commit", "-qam", "main advances")
        later_tree = _git(repo, "rev-parse", "HEAD^{tree}")

        record = cr.build(closure(target, tree), review())
        assert cr.verify(record, repo) == []
        assert cr.compare(record, cr.current_identities(review(), later_tree)) == [f"tree: {tree} -> {later_tree}"]

        wrong = cr.build(closure(target, later_tree), review())
        assert any("has tree" in p for p in cr.verify(wrong, repo))

        absent = cr.build(closure("0" * 40, tree), review())
        assert any("not in this repository's history" in p for p in cr.verify(absent, repo))
        assert _git(repo, "rev-parse", "--is-shallow-repository") == "false"


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
