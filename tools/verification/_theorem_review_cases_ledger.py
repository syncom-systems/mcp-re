# SPDX-License-Identifier: Apache-2.0
"""Cases for the owner-approval ledger.

Cases for `test_theorem_review.py`, which runs them.
"""

from __future__ import annotations

import json
from pathlib import Path

from _review import (
    PREMISE_UNREVIEWED,
    UNBACKED,
    theorem_assurance,
)
from _theorem_review_support import (
    Backing,
    UNIT,
    fingerprints,
    no_premises,
    premise_assurance,
    registry,
    review_for,
    semantics,
)
from pathlib import (
    Path,
)


# --- ledger integrity: a record is backed by what the ledger SAYS (Ruling 34 §7 B) ------


def test_a_premise_review_the_ledger_does_not_sign_is_unbacked():
    """A review-axis record is a file anyone can commit. Without an owner signature over the
    entry's current text it does not make the premise reviewed."""
    unsigned = Backing(**{"ASM-0001": (False, "not signed")})
    state = premise_assurance(backing=unsigned)
    assert state["premise_review"]["ASM-0001"][0] == UNBACKED
    assert state["review"][0] == PREMISE_UNREVIEWED


def test_a_specification_review_the_ledger_refutes_is_unbacked():
    refuted = Backing(**{"THM-0001": (False, "signed only at other text")})
    doc = registry()
    fps = fingerprints(doc)
    digests = semantics(doc, no_premises(doc))
    reviews = {("specification", "THM-0001"): review_for(fps["THM-0001"], semantic=digests["THM-0001"])}
    state = theorem_assurance(
        doc, fps, reviews, {UNIT: ("FRESH", "fixture")}, no_premises(doc), refuted, digests
    )["THM-0001"]
    assert state["specification_review"][0] == UNBACKED
    assert state["currently_verified"] is False


def test_no_ledger_check_is_not_a_pass():
    doc = registry()
    fps = fingerprints(doc)
    digests = semantics(doc, no_premises(doc))
    reviews = {("specification", "THM-0001"): review_for(fps["THM-0001"], semantic=digests["THM-0001"])}
    state = theorem_assurance(
        doc, fps, reviews, {UNIT: ("FRESH", "fixture")}, no_premises(doc), {}, digests
    )["THM-0001"]
    assert state["specification_review"][0] == UNBACKED


def test_the_ledger_signs_entry_text_not_a_subject_name():
    """`ledger_state` against a real-shaped ledger: an entry approval at earlier text does
    not back the entry; at the current text it does; an assumption the ledger only NAMES in
    a ruling's prose is not backed; a theorem with no entry approval keeps its record's
    authority."""
    from _approvals import entry_text, ledger_state, text_digest

    registry_text = (
        '[[assumption]]\nid = "ASM-0001"\ndescription = "now"\n\n'
        "# a comment introducing the next entry\n"
        '[[assumption]]\nid = "ASM-0002"\ndescription = "other"\n'
    )
    current = entry_text(registry_text, "ASM-0001")
    assert current == '[[assumption]]\nid = "ASM-0001"\ndescription = "now"\n'
    old = current.replace("now", "then")
    src = 'verification/policy/assumptions.toml [[assumption]] id = "ASM-0001"'
    stale = [{"source": src, "text": old, "sha256": text_digest(old), "ruling": "r1"}]
    assert ledger_state("ASM-0001", current, stale, allow_ruling=False)[0] is False
    signed = stale + [{"source": src, "text": current, "sha256": text_digest(current),
                       "ruling": "r2"}]
    assert ledger_state("ASM-0001", current, signed, allow_ruling=False)[0] is True
    prose = [{"source": "a ruling", "text": "x", "sha256": text_digest("x"), "ruling": "r",
              "surfaces": ["ASM-0001"]}]
    assert ledger_state("ASM-0001", current, prose, allow_ruling=False)[0] is False
    assert ledger_state("THM-0001", "irrelevant", prose, allow_ruling=True)[0] is True


def test_a_ledger_line_whose_digest_does_not_cover_its_text_is_refused():
    import tempfile

    from _approvals import ApprovalError, load_ledger

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "docs/security").mkdir(parents=True)
        line = {"ruling": "r", "approved_by": "o", "approved": "d", "source": "s",
                "text": "signed", "sha256": "0" * 64}
        (root / "docs/security/owner-approvals-2026-01-01.jsonl").write_text(
            json.dumps(line) + "\n"
        )
        try:
            load_ledger(root)
        except ApprovalError as exc:
            assert "does not cover" in str(exc)
        else:
            raise AssertionError("a forged ledger line was accepted")


def test_the_live_ledger_hashes_and_every_entry_approval_parses():
    from _approvals import entry_subject, load_ledger
    from _manifest import REPO_ROOT

    rows = load_ledger(REPO_ROOT)
    assert rows, "the live ledger is empty — a check over nothing is not a check"
    import tomllib

    for row in rows:
        if entry_subject(row):
            tomllib.loads(row["text"])
