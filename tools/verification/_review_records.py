# SPDX-License-Identifier: Apache-2.0
"""Loading review records: the closed schema check and the directory walk.

A record is dropped, never repaired, when anything about it is off. Dropped means the
subject has no review and derives to `UNREVIEWED`; repairing would invent the provenance
the record exists to carry.
"""

from __future__ import annotations

import json
from pathlib import Path

from _review_model import AXES, RECORD_KEYS, RECORD_REQUIRED, SUBJECT_PREFIX


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and value.startswith("sha256:")


def _schema_ok(raw: dict) -> bool:
    return not set(raw) - RECORD_KEYS and RECORD_REQUIRED <= set(raw)


def _axis_ok(raw: dict) -> bool:
    return raw["axis"] in AXES


def _subject_ok(raw: dict) -> bool:
    subject = raw["subject"]
    prefix = SUBJECT_PREFIX.get(raw["axis"])
    if not isinstance(subject, str):
        return False
    return not prefix or subject.startswith(prefix)


def _fingerprint_ok(raw: dict) -> bool:
    return _is_digest(raw["reviewed_fingerprint"])


def _reviewer_ok(raw: dict) -> bool:
    reviewer = raw.get("reviewer")
    return isinstance(reviewer, str) and bool(reviewer.strip())


def _semantic_fields_ok(raw: dict) -> bool:
    if "review_digest" in raw and not _is_digest(raw["review_digest"]):
        return False
    if "review_components" in raw and not isinstance(raw["review_components"], dict):
        return False
    carries_semantics = "review_digest" in raw or "review_components" in raw
    return not carries_semantics or raw["axis"] == "specification"


#: Run in order: each later check reads a key an earlier one has shown to be present.
_CHECKS = (
    _schema_ok,
    _axis_ok,
    _subject_ok,
    _fingerprint_ok,
    _reviewer_ok,
    _semantic_fields_ok,
)


def valid(raw: object) -> dict | None:
    """One record, or None if anything about it is off. Dropped, never repaired."""
    if not isinstance(raw, dict):
        return None
    return raw if all(check(raw) for check in _CHECKS) else None


def load_reviews(root: Path) -> dict[tuple[str, str], dict]:
    """Every review record, keyed by `(axis, subject)`.

    A malformed record is DROPPED, so its subject has no review, which derives to
    `UNREVIEWED`. Raising instead would let one bad file hide every good one; repairing
    would invent the provenance the record exists to carry.
    """
    out: dict[tuple[str, str], dict] = {}
    if not root.exists():
        return out
    for path in sorted(root.rglob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        record = valid(raw)
        if record is None:
            continue
        out[(record["axis"], record["subject"])] = record
    return out
