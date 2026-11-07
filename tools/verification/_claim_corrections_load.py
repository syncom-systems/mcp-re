# SPDX-License-Identifier: Apache-2.0
"""Loading the correction records on disk.

UNPARSABLE IS A FAILURE, not an omission. `_review.load_reviews` may drop a bad record
because dropping one leaves an axis UNREVIEWED, which withholds establishment. Here the
opposite is true: dropping a record would remove the thing a gate is about to consult, and
the gate would then report the plain staleness defect for a reason that is not the real one.
So this raises.
"""

from __future__ import annotations

import json
from pathlib import Path

from _claim_corrections_authority import ledger_defect, packet_defect
from _claim_corrections_schema import CorrectionError, validate

_LEDGER_PACKET_PREFIX = "docs/security/owner-approvals-"


class _OwnerLedger:
    """The owner-approval ledger and the theorems registry, read once and only when a record
    names the ledger as its packet."""

    def __init__(self, repo_root: Path) -> None:
        self._repo_root = repo_root
        self._ledger: list[dict] | None = None
        self._theorems: dict = {}

    def _load(self) -> list[dict]:
        import _registries
        from _approvals import ApprovalError, load_ledger

        try:
            ledger = load_ledger(self._repo_root)
        except ApprovalError as exc:
            raise CorrectionError(f"owner-approval ledger: {exc}") from exc
        self._theorems = _registries.document("theorems", self._repo_root)
        return ledger

    def defect(self, record: dict, where: str) -> str | None:
        if self._ledger is None:
            self._ledger = self._load()
        return ledger_defect(record, self._ledger, self._theorems, where)


def _read_record(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorrectionError(f"{path.name}: unreadable ({exc})") from exc
    return validate(raw, path.name)


def _tree_defect(record: dict, repo_root: Path, where: str, owner: _OwnerLedger) -> str | None:
    defect = packet_defect(record, repo_root, where)
    if defect:
        return defect
    if str(record["packet"]).startswith(_LEDGER_PACKET_PREFIX):
        return owner.defect(record, where)
    return None


def load_corrections(root: Path, repo_root: Path | None = None) -> dict[str, list[dict]]:
    """Every record on disk, grouped by subject, ordered by the chain they form.

    UNPARSABLE IS A FAILURE, not an omission. `_review.load_reviews` may drop a bad record
    because dropping one leaves an axis UNREVIEWED, which withholds establishment. Here the
    opposite is true: dropping a record would remove the thing a gate is about to consult,
    and the gate would then report the plain staleness defect for a reason that is not the
    real one. So this raises.
    """
    out: dict[str, list[dict]] = {}
    if not root.is_dir():
        return out
    owner = _OwnerLedger(repo_root) if repo_root is not None else None
    for path in sorted(root.glob("*.json")):
        record = _read_record(path)
        if owner is not None:
            defect = _tree_defect(record, repo_root, path.name, owner)
            if defect:
                raise CorrectionError(defect)
        out.setdefault(str(record["subject"]), []).append(record)
    return out
