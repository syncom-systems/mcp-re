# SPDX-License-Identifier: Apache-2.0
"""The claim-correction record schema: the closed key sets, the authorities a record may
claim, and the validation that refuses every record outside them.

Validation raises on the first defect, in a fixed order, and never repairs: a record this
module cannot read is a failure, not an omission.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

#: Where correction records live — in the tree, for the reason `_review` gives: a record that
#: is not in the tree cannot be audited from a clone.
#:
#: DELIBERATELY NOT UNDER `verification/reviews/`, and `scripts/registry_approval_gate.py`
#: is why. That gate requires every record under `reviews/` to name a `reviewed_fingerprint`,
#: because "a review that does not name what it reviewed approves nothing in particular" — and
#: it caught these records on their first CI run. It was right. A correction is NOT a review;
#: it is a recorded delta ON one, and filing it beside the approvals invites exactly the
#: confusion the gate exists to prevent.
CORRECTIONS_DIR = ("claim-corrections",)

#: The record schema, CLOSED. Same rule as `_review_model.RECORD_KEYS`: a key outside this set is
#: a fact this schema cannot compare, and a record carrying one would be read as authorizing
#: something it never described.
_KEYS = {
    "subject",
    "authority",
    "ruling",
    "packet",
    "from_fingerprint",
    "to_fingerprint",
    "changed_components",
    "corrections",
    "reason",
    "root_consequence_unchanged",
    "product_behavior_unchanged",
    "severity_before",
    "severity_after",
    "severity_justification",
    "dependency_correction",
}
_OPTIONAL = {"severity_justification", "dependency_correction"}

#: The authorities a record may claim, CLOSED. A record naming anything else is refused
#: rather than read as some default — "authorized by something" is not an authority.
#:
#:   adr-068-phase1               the 2026-09-18 Phase-1 ruling quoted above: precision and
#:                                dependency corrections that leave the promise intact.
#:   bazel-lane-wording-2026-09-29  the owner's Bazel-only-migration ruling: a claim's naming
#:                                of the lane that MEASURES it moved from Cargo to Bazel, and
#:                                nothing else in the proposition or its scope did — directly,
#:                                or through a premise that moved only so.
AUTHORITIES = {"adr-068-phase1", "bazel-lane-wording-2026-09-29"}

#: What the gate may be asked to accept a correction over. `theorem_review_requirement` is
#: deliberately absent: relaxing WHO must review a claim is not a precision correction, and a
#: record could not assert it away.
CORRECTABLE_COMPONENTS = {"theorem_claim", "theorem_dependencies"}

#: A per-correction entry inside `corrections`, CLOSED.
_CORRECTION_KEYS = {"id", "field", "old", "new", "reason"}

#: The fields of a claim a correction may be about.
_CORRECTION_FIELDS = {"statement", "security_consequence", "scope", "depends_on"}


class CorrectionError(Exception):
    """A record this module refuses. Fail-closed: never a silently ignored file."""


def corrections_root(repo_root: Path) -> Path:
    return repo_root.joinpath("verification", *CORRECTIONS_DIR)



@dataclass(frozen=True)
class _ClosedKeys:
    """A closed key set: nothing outside `allowed`, everything in `required`."""

    allowed: set[str]
    required: set[str]
    missing_label: str

    def check(self, record: dict, where: str) -> None:
        unknown = set(record) - self.allowed
        if unknown:
            raise CorrectionError(f"{where}: unknown key(s) {sorted(unknown)}")
        missing = self.required - set(record)
        if missing:
            raise CorrectionError(f"{where}: missing {self.missing_label} {sorted(missing)}")


_RECORD_SCHEMA = _ClosedKeys(_KEYS, _KEYS - _OPTIONAL, "required key(s)")
_ENTRY_SCHEMA = _ClosedKeys(_CORRECTION_KEYS, _CORRECTION_KEYS, "key(s)")


def _check_shape(raw: object, where: str) -> dict:
    if not isinstance(raw, dict):
        raise CorrectionError(f"{where}: not a JSON object")
    _RECORD_SCHEMA.check(raw, where)
    return raw


def _check_authority(raw: dict, where: str) -> None:
    if not str(raw["subject"]).startswith("THM-"):
        raise CorrectionError(f"{where}: subject {raw['subject']!r} is not a theorem id")
    if raw["authority"] not in AUTHORITIES:
        raise CorrectionError(
            f"{where}: authority {raw['authority']!r} is not one of {sorted(AUTHORITIES)}. "
            f"A record may not name an authority this module cannot check."
        )


def _check_stated_reasons(raw: dict, where: str) -> None:
    if not str(raw.get("ruling", "")).strip():
        raise CorrectionError(
            f"{where}: `ruling` is empty. The record must name the ruling that authorizes "
            f"it, or it authorizes itself."
        )
    if not str(raw.get("reason", "")).strip():
        raise CorrectionError(
            f"{where}: `reason` is empty. A correction without the reason from the "
            f"decomposition is an arbitrary edit with a filename."
        )


def _check_flags(raw: dict, where: str) -> None:
    for flag in ("root_consequence_unchanged", "product_behavior_unchanged"):
        if raw.get(flag) is not True:
            raise CorrectionError(
                f"{where}: `{flag}` is {raw.get(flag)!r}, not true. The ruling authorizes "
                f"corrections that leave the accepted promise and the product boundary "
                f"alone; a record that cannot assert both is outside it and is an owner "
                f"escalation, not a correction."
            )


def _check_changed_components(raw: dict, where: str) -> None:
    changed = raw.get("changed_components")
    if not isinstance(changed, list) or not changed:
        raise CorrectionError(f"{where}: `changed_components` must be a non-empty list")
    outside = sorted(set(map(str, changed)) - CORRECTABLE_COMPONENTS)
    if outside:
        raise CorrectionError(
            f"{where}: `changed_components` names {outside}, outside "
            f"{sorted(CORRECTABLE_COMPONENTS)}. Those are not corrections this ruling covers."
        )


def _check_severity(raw: dict, where: str) -> None:
    if raw["severity_before"] == raw["severity_after"]:
        return
    if not str(raw.get("severity_justification", "")).strip():
        raise CorrectionError(
            f"{where}: severity moves {raw['severity_before']!r} -> "
            f"{raw['severity_after']!r} with no `severity_justification`. The ruling allows "
            f"a severity change only when independently justified."
        )


def _check_entry_keys(entry: object, ewhere: str) -> dict:
    if not isinstance(entry, dict):
        raise CorrectionError(f"{ewhere}: not an object")
    _ENTRY_SCHEMA.check(entry, ewhere)
    return entry


def _check_entry_identity(entry: dict, ewhere: str, seen: set[str]) -> None:
    if entry["field"] not in _CORRECTION_FIELDS:
        raise CorrectionError(
            f"{ewhere}: field {entry['field']!r} not one of {sorted(_CORRECTION_FIELDS)}"
        )
    if entry["id"] in seen:
        raise CorrectionError(f"{ewhere}: duplicate correction id {entry['id']!r}")
    seen.add(entry["id"])


def _check_entry_change(entry: dict, ewhere: str) -> None:
    if entry["old"] == entry["new"]:
        raise CorrectionError(
            f"{ewhere}: `old` equals `new`. A correction that changes nothing is a row "
            f"that will outlive the reason it was written for."
        )
    if not str(entry.get("reason", "")).strip():
        raise CorrectionError(f"{ewhere}: `reason` is empty")


def _check_entry(entry: object, ewhere: str, seen: set[str]) -> None:
    record = _check_entry_keys(entry, ewhere)
    _check_entry_identity(record, ewhere, seen)
    _check_entry_change(record, ewhere)


def _check_entries(raw: dict, where: str) -> None:
    entries = raw.get("corrections")
    if not isinstance(entries, list) or not entries:
        raise CorrectionError(
            f"{where}: `corrections` is empty. The durable old->new record IS the artefact; "
            f"a record with no entries documents nothing."
        )
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        _check_entry(entry, f"{where} corrections[{index}]", seen)


def validate(raw: object, where: str) -> dict:
    """`raw` as a correction record, or `CorrectionError` for the first thing wrong with it."""
    record = _check_shape(raw, where)
    _check_authority(record, where)
    _check_stated_reasons(record, where)
    _check_flags(record, where)
    _check_changed_components(record, where)
    _check_severity(record, where)
    _check_entries(record, where)
    return record
