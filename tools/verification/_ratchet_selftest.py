# SPDX-License-Identifier: Apache-2.0
"""The selftest of the ratchet register (`_ratchet.py --selftest`): its three baseline states,
its schema refusals and its transition pairing, each exercised against a scratch git repository."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from _ratchet import (
    Absent,
    Present,
    Register,
    RegisterError,
    Schema,
    Unreadable,
    transitions,
)

SCHEMA = Schema(
    table="debt",
    key="path",
    required=frozenset({"path", "status"}),
    fields=frozenset({"path", "status", "review_ref", "n"}),
    statuses=("unreviewed", "reviewed-exception"),
    reviewed=frozenset({"reviewed-exception"}),
)
BODY = '[[debt]]\npath = "a"\nstatus = "unreviewed"\nn = 1\n'


class Cases:
    """Prints one line per case and counts the ones that failed."""

    def __init__(self) -> None:
        self.failures = 0

    def __call__(self, label: str, ok: bool, detail: object = None) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            self.failures += 1
            if detail is not None:
                print(f"        got {detail!r}")


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "HOME": str(root),
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "selftest",
             "GIT_AUTHOR_EMAIL": "selftest@example.invalid", "GIT_COMMITTER_NAME": "selftest",
             "GIT_COMMITTER_EMAIL": "selftest@example.invalid"},
    )


def _commit(root: Path, message: str) -> None:
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)


def _baseline_states(case: Cases) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        reg = Register("config/debt.toml", SCHEMA, root)
        case("an absent register file is empty", reg.current() == {}, reg.current())

        not_a_repo = reg.at("HEAD")
        case("outside a repository the baseline is Unreadable, not Absent",
             isinstance(not_a_repo, Unreadable), not_a_repo)

        _git(root, "init", "-q")
        (root / "README.md").write_text("x\n")
        _commit(root, "first")
        absent = reg.at("HEAD")
        case("a resolving revision without the register is Absent", isinstance(absent, Absent), absent)
        bad_ref = reg.at("no-such-ref")
        case("a revision that does not resolve is Unreadable", isinstance(bad_ref, Unreadable), bad_ref)

        (root / "config").mkdir()
        reg.path.write_text(BODY)
        _commit(root, "second")
        present = reg.at("HEAD")
        case("a revision holding the register is Present with its entries",
             isinstance(present, Present)
             and present.entries == {"a": {"path": "a", "status": "unreviewed", "n": 1}},
             present)
        reg.path.write_text("[[debt]\n")
        _commit(root, "third")
        torn = reg.at("HEAD")
        case("an unparsable register at the revision is Unreadable", isinstance(torn, Unreadable), torn)

        reg.path.write_text(BODY + BODY)
        try:
            reg.current()
            case("two entries under one key are refused", False)
        except RegisterError:
            case("two entries under one key are refused", True)


def _schema_refusals(case: Cases) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        reg = Register("config/debt.toml", SCHEMA, root)
        (root / "docs").mkdir()
        (root / "docs" / "r.md").write_text("EX-1 the record\n")
        entries = {
            "ok": {"path": "ok", "status": "reviewed-exception", "review_ref": "EX-1 in docs/r.md"},
            "bare": {"path": "bare", "status": "reviewed-exception", "review_ref": "docs/r.md"},
            "noref": {"path": "noref", "status": "reviewed-exception"},
            "gone": {"path": "gone", "status": "reviewed-exception", "review_ref": "EX-1 in docs/x.md"},
            "norecord": {"path": "norecord", "status": "reviewed-exception", "review_ref": "EX-9 in docs/r.md"},
            "status": {"path": "status", "status": "bogus"},
            "field": {"path": "field", "status": "unreviewed", "exception_ref": "x"},
            "missing": {"path": "missing"},
        }
        found = reg.problems(entries)
        flagged = {p.split(":", 1)[0] for p in found}
        case("a resolving review_ref, record or bare document, passes", not flagged & {"ok", "bare"}, found)
        for key in ("noref", "gone", "norecord", "status", "field", "missing"):
            case(f"schema refuses `{key}`", key in flagged, found)


def _lost_blob(case: Cases) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        reg = Register("config/debt.toml", SCHEMA, root)
        _git(root, "init", "-q")
        (root / "config").mkdir()
        reg.path.write_text(BODY)
        _commit(root, "first")
        blob = subprocess.run(
            ["git", "rev-parse", "HEAD:config/debt.toml"], cwd=root, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        (root / ".git" / "objects" / blob[:2] / blob[2:]).unlink()
        lost = reg.at("HEAD")
        case("a register the revision names but whose blob is unreadable is Unreadable, not Absent",
             isinstance(lost, Unreadable), lost)


def _pairing(case: Cases) -> None:
    case(
        "transitions pair only the entries both registers hold",
        transitions({"a": {"s": 1}, "b": {"s": 2}}, {"b": {"s": 3}, "c": {"s": 4}})
        == [("b", {"s": 2}, {"s": 3})],
    )


def selftest() -> int:
    case = Cases()
    _baseline_states(case)
    _schema_refusals(case)
    _lost_blob(case)
    _pairing(case)
    if case.failures:
        print(f"ratchet register: SELFTEST FAILED ({case.failures})")
        return 1
    print("ratchet register: selftest passed")
    return 0
