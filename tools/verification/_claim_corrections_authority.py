# SPDX-License-Identifier: Apache-2.0
"""What backs a correction record's `packet`: the file the tree must hold, and — when the
packet is the owner-approval ledger — what that ledger actually says."""

from __future__ import annotations

import tomllib
from pathlib import Path


def packet_defect(record: dict, repo_root: Path, where: str) -> str | None:
    """The packet a record names must be a file this tree holds.

    The same rule the module-size and obligation registries follow for `review_ref` and
    `decomposition_ref`: a record that points at reasoning nobody can read is a record whose
    reason cannot be checked, and the reason IS the thing that makes it a correction rather
    than an edit.
    """
    packet = str(record.get("packet", "")).strip()
    if not packet:
        return f"{where}: `packet` is empty"
    if not (repo_root / packet).is_file():
        return (
            f"{where}: names packet {packet!r}, which this tree does not hold. A correction "
            f"points at the decomposition that justifies it, not at a memory of one."
        )
    return None


def depends_closure(subject: str, theorems: dict) -> set[str]:
    """`subject`'s transitive `depends_on` premises."""
    by_id = {row["id"]: row for row in theorems.get("theorem", [])}
    seen: set[str] = set()
    stack = list(by_id.get(subject, {}).get("depends_on", []))
    while stack:
        dep = stack.pop()
        if dep in seen:
            continue
        seen.add(dep)
        stack.extend(by_id.get(dep, {}).get("depends_on", []))
    return seen


def _corrects_own_claim(record: dict) -> bool:
    return "theorem_claim" in record.get("changed_components", [])


def _relevant_subjects(record: dict, theorems: dict) -> set[str]:
    subject = str(record["subject"])
    relevant = {subject}
    if not _corrects_own_claim(record):
        relevant |= depends_closure(subject, theorems)
    return relevant


def _signs_corrected_text(record: dict, entries: list[dict]) -> bool:
    for row in entries:
        try:
            signed = tomllib.loads(row["text"]).get("theorem", [{}])[0]
        except tomllib.TOMLDecodeError:
            continue
        if all(signed.get(c["field"]) == c["new"] for c in record["corrections"]):
            return True
    return False


def _unspoken_defect(
    rows: list[dict], relevant: set[str], subject: str, packet_and_where: tuple[str, str]
) -> str | None:
    """The refusal when no ledger line in the packet speaks about the subject or a premise."""
    from _approvals import names

    if any(names(row, other) for row in rows for other in relevant):
        return None
    packet, where = packet_and_where
    return (
        f"{where}: names packet {packet!r}, and no line there speaks about {subject}"
        f"{' or a premise it depends on' if len(relevant) > 1 else ''}. An approval "
        f"of something else is not this correction's authority."
    )


def ledger_defect(record: dict, ledger: list[dict], theorems: dict, where: str) -> str | None:
    """A record whose `packet` is the owner-approval ledger must be backed by what that
    ledger SAYS, not by the file existing.

    The ledger must hold a line that speaks about this correction: one naming the subject,
    or — for a dependency correction — a premise in its `depends_on` closure, since that is
    the claim whose approved change moved this one. An own-claim correction against a ledger
    that carries an ENTRY approval for the subject must match it field for field: every
    corrected field's `new` text is what the signed entry says. A line about something else,
    or a signature over different text, is not this record's authority.
    """
    from _approvals import entry_subject

    packet = str(record["packet"])
    rows = [row for row in ledger if row["_file"] == packet]
    subject = str(record["subject"])
    relevant = _relevant_subjects(record, theorems)
    unspoken = _unspoken_defect(rows, relevant, subject, (packet, where))
    if unspoken:
        return unspoken
    if not _corrects_own_claim(record):
        return None
    entries = [row for row in rows if entry_subject(row) == subject]
    if not entries or _signs_corrected_text(record, entries):
        return None
    return (
        f"{where}: the ledger's entry approval(s) for {subject} in {packet!r} do not sign "
        f"the corrected text this record writes. A signature over different text is "
        f"evidence about that text only."
    )
