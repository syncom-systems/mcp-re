# SPDX-License-Identifier: Apache-2.0
"""Deriving one review state: whether a record covers its subject AS IT STANDS, and if not,
what moved.

Three records are compared, each against its own current value: the claim fingerprint
(`derive_review_state`, then the owner-approval ledger in `backed_review_state`), an
assumption's entry digest (`assumption_review_state`), and the semantic evidence digest
(`semantic_review_state`). `combined_review` is the conjunction the theorem axis reports.
"""

from __future__ import annotations

from _review_model import (
    COMPONENT_CAUSE,
    NO_SEMANTIC_DIGEST,
    PREMISE_UNREVIEWED,
    REVIEWED,
    STALE_REVIEW,
    STALE_SEMANTICS,
    UNBACKED,
    UNKNOWN,
    UNREVIEWED,
    by_precedence,
)


def derive_review_state(current: dict, record: dict | None) -> tuple[str, str]:
    """Whether a review covers the subject AS IT STANDS, and if not, what moved.

    `current` is a fingerprint mapping (`fingerprint` + `components`), the same shape
    `_fingerprint` produces for both units and theorems.
    """
    if record is None:
        return UNREVIEWED, "no review record: this has never been reviewed"
    recorded = record.get("components")
    if isinstance(recorded, dict) and recorded:
        return _compare_components(current, record, recorded)
    return _without_components(current, record)


def _compare_components(current: dict, record: dict, recorded: dict) -> tuple[str, str]:
    comparable = {
        name: value for name, value in current["components"].items() if name != "encoding_version"
    }
    missing = sorted(name for name in comparable if name not in recorded)
    if missing:
        return (
            UNKNOWN,
            f"the review records no `{', '.join(missing)}`: it predates the current "
            f"encoding, so what was reviewed cannot be compared",
        )
    differing = sorted(name for name, value in comparable.items() if recorded[name] != value)
    if differing:
        cause = by_precedence({COMPONENT_CAUSE.get(name, "STALE_INPUT") for name in differing})
        return cause, "changed since review: " + ", ".join(differing)
    if record["reviewed_fingerprint"] != current["fingerprint"]:
        # Every recorded component matches and the digest does not: the encoding itself
        # changed, so the comparison means something different from what it meant when
        # the reviewer signed. Same rule as `_graph`, and for the same reason.
        return (
            UNKNOWN,
            "every recorded component matches but the fingerprint does not: the "
            "encoding changed, so what was reviewed cannot be compared",
        )
    return REVIEWED, f"reviewed at {current['fingerprint'][7:23]}"


def _without_components(current: dict, record: dict) -> tuple[str, str]:
    # A record with no components can still say WHETHER it is current; it just cannot say
    # what moved. That is a weaker record, not an invalid one, and it must never read as
    # fresher than one that can name the cause.
    if record["reviewed_fingerprint"] != current["fingerprint"]:
        return (
            STALE_REVIEW,
            f"reviewed at {record['reviewed_fingerprint'][7:23]} but this now fingerprints "
            f"{current['fingerprint'][7:23]}; the record names no components, so what moved "
            f"cannot be derived",
        )
    return REVIEWED, f"reviewed at {current['fingerprint'][7:23]}"


def backed_review_state(
    current: dict, record: dict | None, backing: tuple[bool, str] | None
) -> tuple[str, str]:
    """`derive_review_state`, then the ledger cross-check.

    A record that matches the tree is `REVIEWED` only if `backing` — the subject's
    `_approvals.ledger_state` — says the owner's signature covers it. No backing supplied is
    not backed: the absence of a check is not a pass.
    """
    state, reason = derive_review_state(current, record)
    if state != REVIEWED:
        return state, reason
    if backing is None:
        return UNBACKED, "no owner-approval ledger check was supplied for this subject"
    backed, why = backing
    if not backed:
        return UNBACKED, f"{reason}, but {why}"
    return REVIEWED, f"{reason}; {why}"


def assumption_review_state(
    assumption_id: str,
    digest: str,
    reviews: dict[tuple[str, str], dict],
    backing: dict[str, tuple[bool, str]],
) -> tuple[str, str]:
    """One premise on the assumption axis: its review record against the entry's current
    digest (`_fingerprint.assumption_digest`), cross-checked against the ledger."""
    return backed_review_state(
        {"fingerprint": digest, "components": {"assumption_entry": digest}},
        reviews.get(("assumption", assumption_id)),
        backing.get(assumption_id),
    )


def semantic_review_state(current: dict | None, record: dict | None) -> tuple[str, str]:
    """Whether the owner's specification review covers the semantic evidence AS IT STANDS.

    `current` is `_fingerprint.review_digest` for the theorem, or None when it could not be
    computed. The record must carry the `review_digest` the reviewer read at; a record that
    does not is `NO_SEMANTIC_DIGEST`, whatever its claim fingerprint says.
    """
    if record is None:
        return UNREVIEWED, "no review record: this has never been reviewed"
    if current is None:
        return UNKNOWN, "the semantic evidence digest could not be computed"
    reviewed = record.get("review_digest")
    if reviewed is None:
        return (
            NO_SEMANTIC_DIGEST,
            "the review names the claim but not the supporting code, tests and proved "
            "symbols it was read against",
        )
    if reviewed == current["fingerprint"]:
        return REVIEWED, f"semantic evidence reviewed at {reviewed[7:23]}"
    return STALE_SEMANTICS, "changed since review: " + semantic_delta(
        current["components"], record.get("review_components")
    )


def _dict_or_empty(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _claim_moves(current: dict, recorded: dict) -> list[str]:
    names = ("theorem_claim", "theorem_dependencies", "theorem_review_requirement")
    return [name for name in names if recorded.get(name) != current.get(name)]


def _premise_moves(current: dict, recorded: dict) -> list[str]:
    before = _dict_or_empty(recorded.get("premises"))
    after = current.get("premises", {})
    return [
        f"premise {asm}"
        for asm in sorted(set(before) | set(after))
        if before.get(asm) != after.get(asm)
    ]


def _unit_move(unit: str, old: object, new: object) -> str | None:
    if not isinstance(old, dict) or not isinstance(new, dict):
        return f"unit://{unit} (added or removed)"
    names = sorted(n for n in set(old) | set(new) if old.get(n) != new.get(n))
    return f"unit://{unit} {'+'.join(names)}" if names else None


def _unit_moves(current: dict, recorded: dict) -> list[str]:
    was = _dict_or_empty(recorded.get("supporting_semantics"))
    now = current.get("supporting_semantics", {})
    moves = (_unit_move(unit, was.get(unit), now.get(unit)) for unit in sorted(set(was) | set(now)))
    return [move for move in moves if move is not None]


def semantic_delta(current: dict, recorded: object) -> str:
    """What moved between the reviewed and the current semantic digest, as precisely as the
    record allows: each supporting unit's components by name, then the premises and claim."""
    if not isinstance(recorded, dict):
        return "the record names no components, so what moved cannot be derived"
    moved = [
        *_claim_moves(current, recorded),
        *_premise_moves(current, recorded),
        *_unit_moves(current, recorded),
    ]
    if recorded.get("encoding_version") != current.get("encoding_version"):
        moved.append("review encoding")
    return ", ".join(moved) or "the digest differs and no recorded component does"


def combined_review(
    spec: tuple[str, str],
    closure: dict[str, str] | None,
    premise_review: dict[str, tuple[str, str]],
    semantic: tuple[str, str],
) -> tuple[str, str]:
    """REVIEW_CURRENT: the current claim, its current premises, and its current supporting
    semantic evidence are what the owner reviewed. The claim leads when it fails, then the
    premises, then the semantics — the order a re-read takes."""
    spec_state, spec_reason = spec
    if spec_state != REVIEWED:
        return spec_state, spec_reason
    if closure is None:
        return UNKNOWN, "the premise closure was not computed, so it cannot be compared"
    open_premises = sorted(
        f"{asm} {state}" for asm, (state, _) in premise_review.items() if state != REVIEWED
    )
    if open_premises:
        return PREMISE_UNREVIEWED, "premise(s) not reviewed as they stand: " + ", ".join(
            open_premises
        )
    if semantic[0] != REVIEWED:
        return semantic
    return REVIEWED, f"{spec_reason}; {len(premise_review)} premise(s) reviewed; {semantic[1]}"
