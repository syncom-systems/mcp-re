# SPDX-License-Identifier: Apache-2.0
"""The review standing of each theorem: reviewed, or carried there by a recorded correction."""

from __future__ import annotations

from dataclasses import dataclass, field

from _claim_surface.config import REPO
from _claim_surface.errors import Failure

from _claim_corrections import (  # noqa: E402
    CorrectionError,
    chain,
    corrections_root,
    load_corrections,
)
from _fingerprint import fingerprint_theorem  # noqa: E402
from _manifest import ManifestError, load_verification  # noqa: E402
from _review import REVIEWED, derive_review_state, load_reviews, review_root  # noqa: E402
from _theorems import load_theorems  # noqa: E402


@dataclass(frozen=True)
class Standing:
    """Per theorem: its specification-review state, and whether a correction record carries it."""

    review_states: dict[str, tuple[str, str]]
    corrected: dict[str, tuple[bool, str]] = field(default_factory=dict)

    def unreviewed(self, theorem: str) -> tuple[str, str, str] | None:
        """`(state, reason, why no correction carries it)`, or `None` when the claim stands.

        A claim stands when the owner reviewed its present form or a recorded correction
        carries the approval there.
        """
        state, reason = self.review_states.get(theorem, ("MISSING", "no review record"))
        if state == REVIEWED:
            return None
        accepted, why = self.corrected.get(theorem, (False, "no correction record"))
        if accepted:
            return None
        return state, reason, why


@dataclass(frozen=True)
class Registry:
    """What the theorem registry and its review records say, derived once."""

    roots: list[str]
    theorems: dict
    standing: Standing
    reviewed_subjects: set[str]

    def carried_roots(self) -> int:
        """How many declared roots stand only because a recorded correction carries them."""
        return sum(
            1
            for root in self.roots
            if self.standing.corrected.get(root, (False, ""))[0]
            and self.standing.review_states[root][0] != REVIEWED
        )


def _load_registry_theorems() -> dict:
    try:
        doc = load_verification()
        return load_theorems(
            {unit["id"] for unit in doc.get("unit", [])},
            [e for e in doc.get("edge", []) if e.get("kind") == "PROOF_DEPENDENCY"],
        )
    except ManifestError as exc:
        raise Failure(f"FAIL: {exc}") from exc


def _declared_roots(theorems: dict) -> list[str]:
    roots = list(theorems.get("root_theorems", []))
    if not roots:
        # An empty root set is the emptiest registry reading as the greenest, one level up.
        raise Failure(
            "FAIL: `root_theorems` is empty. A repository that declares no system promise "
            "has no claim surface to be consistent with, and this gate must not report "
            "that as agreement."
        )
    return roots


def _load_records() -> dict:
    try:
        return load_corrections(corrections_root(REPO), REPO)
    except CorrectionError as exc:
        # UNPARSABLE IS A FAILURE. A dropped record would make the staleness defect below
        # report a reason that is not the real one.
        raise Failure(f"FAIL: {exc}") from exc


def _refuse_dead_records(corrections: dict, fingerprints: dict, standing: Standing) -> None:
    """A DEAD RECORD IS REFUSED WHEREVER IT SITS.

    The §2 check only consults `corrected` for theorems the boundary publishes, so a record
    for any other theorem — or one whose chain stopped closing — would sit unread. The
    honest exception is a correction the owner has since REVIEWED at the new fingerprint:
    the chain then no longer closes because its `from` is the superseded review, and the
    record is history rather than authority. Deleting it to satisfy a gate would destroy
    the audit trail this register exists to keep.
    """
    dead = sorted(
        subject
        for subject in corrections
        if subject in fingerprints
        and not standing.corrected[subject][0]
        and standing.review_states[subject][0] != REVIEWED
    )
    if dead:
        raise Failure(
            *(
                f"FAIL: claim-correction record(s) for {subject} authorize no live "
                f"transition and the claim is not reviewed as it stands: "
                f"{standing.corrected[subject][1]}. A record that carries nothing is a row "
                f"nothing can retire."
                for subject in dead
            )
        )


def _refuse_orphaned_records(corrections: dict, fingerprints: dict) -> None:
    """A record for a theorem the registry does not declare authorizes a transition of nothing."""
    orphaned = sorted(set(corrections) - set(fingerprints))
    if orphaned:
        raise Failure(
            f"FAIL: claim-correction record(s) name {orphaned}, which the registry does not "
            f"declare. A correction to a theorem that does not exist is a row nothing can "
            f"ever retire."
        )


def _review_states(fingerprints: dict, reviews: dict) -> dict[str, tuple[str, str]]:
    return {
        theorem: derive_review_state(fingerprints[theorem], reviews.get(("specification", theorem)))
        for theorem in fingerprints
    }


def _correction_chains(corrections: dict, fingerprints: dict, reviews: dict) -> dict:
    """Per theorem, whether its recorded corrections close from the owner's review to now."""
    return {
        theorem: chain(
            corrections.get(theorem, []),
            (reviews.get(("specification", theorem)) or {}).get("reviewed_fingerprint"),
            fingerprints[theorem]["fingerprint"],
        )
        for theorem in fingerprints
    }


def derive_registry() -> Registry:
    """Load the registry and the review standing of every theorem, or raise `Failure`."""
    theorems = _load_registry_theorems()
    roots = _declared_roots(theorems)
    fingerprints = {
        row["id"]: fingerprint_theorem(row, theorems) for row in theorems.get("theorem", [])
    }
    reviews = load_reviews(review_root(REPO))
    corrections = _load_records()
    standing = Standing(
        _review_states(fingerprints, reviews),
        _correction_chains(corrections, fingerprints, reviews),
    )
    _refuse_dead_records(corrections, fingerprints, standing)
    _refuse_orphaned_records(corrections, fingerprints)
    reviewed_subjects = {
        theorem for theorem in fingerprints if reviews.get(("specification", theorem)) is not None
    }
    return Registry(roots, theorems, standing, reviewed_subjects)
