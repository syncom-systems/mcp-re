# SPDX-License-Identifier: Apache-2.0
"""Selftest: the derived half enforces what moved, reviewed once, and nothing else."""

from __future__ import annotations

from dataclasses import dataclass

from _claim_surface.movement import Moved, claim_components, moved_claims, movement_defects
from _claim_surface.standing import Standing

from _review import REVIEWED  # noqa: E402

BOTH = {"THM-0001", "THM-0002"}
STALE = {t: ("STALE_CLAIM", "changed since review") for t in sorted(BOTH)}


def thm(tid: str, **overrides) -> dict:
    """A well-formed theorem row; `overrides` replaces any claim field."""
    row = {
        "id": tid, "statement": "s", "security_consequence": "c",
        "scope": "sc", "depends_on": [], "review_requirement": "owner",
    }
    row.update(overrides)
    return row


BASE_DOC = {"theorem": [thm("THM-0001"), thm("THM-0002", depends_on=["THM-0001"])]}
#: A premise's scope narrows. THM-0001's OWN claim moved; THM-0002 moved only through its
#: dependency closure and is exactly the class the old reach never saw.
AFTER_DOC = {
    "theorem": [thm("THM-0001", scope="narrower"), thm("THM-0002", depends_on=["THM-0001"])]
}


@dataclass(frozen=True)
class Fixture:
    base: dict[str, dict]
    cascade: Moved


def build_fixture() -> Fixture:
    base, _ = claim_components(BASE_DOC)
    after, _ = claim_components(AFTER_DOC)
    return Fixture(base, moved_claims(base, after))


def check_well_formed_row_is_measurable(fx: Fixture) -> str | None:
    _, bad = claim_components(BASE_DOC)
    return f"a well-formed row read as unmeasurable: {bad}" if bad else None


def check_cascade_reaches_dependents(fx: Fixture) -> str | None:
    if [t for t, _ in fx.cascade] != ["THM-0001", "THM-0002"]:
        return f"the cascade measured {fx.cascade!r}"
    if dict(fx.cascade)["THM-0001"] != ["theorem_claim"]:
        return f"the source moved on {dict(fx.cascade)['THM-0001']!r}"
    if dict(fx.cascade)["THM-0002"] != ["theorem_dependencies"]:
        return f"the dependent moved on {dict(fx.cascade)['THM-0002']!r}"
    return None


def check_uncarried_movement_is_enforced(fx: Fixture) -> str | None:
    """Moved, reviewed once, nothing carries it -> BOTH are defects, not just the source."""
    defects = movement_defects(fx.cascade, Standing(STALE), BOTH)
    if len(defects) != 2 or not any("THM-0002" in d for d in defects):
        return f"the dependency-only movement was not enforced: {defects}"
    return None


def check_rereview_silences(fx: Fixture) -> str | None:
    reviewed = Standing({t: (REVIEWED, "reviewed") for t in BOTH})
    if movement_defects(fx.cascade, reviewed, BOTH):
        return "a re-reviewed moved claim still failed"
    return None


def check_correction_silences(fx: Fixture) -> str | None:
    carried = Standing(STALE, {t: (True, "carried") for t in BOTH})
    if movement_defects(fx.cascade, carried, BOTH):
        return "a recorded correction did not carry a moved claim"
    return None


def check_unreviewed_is_silent(fx: Fixture) -> str | None:
    """No approval to invalidate, and inventing one would make this an establishment control."""
    if movement_defects(fx.cascade, Standing(STALE), set()):
        return "an unreviewed theorem was held to a review it never had"
    return None


def check_equality_is_silent(fx: Fixture) -> str | None:
    if moved_claims(fx.base, fx.base):
        return "an identical registry reported movement"
    return None


def check_unfingerprintable_is_unmeasurable(fx: Fixture) -> str | None:
    broken, broken_ids = claim_components({"theorem": [{"id": "THM-0003", "statement": "s"}]})
    if broken or broken_ids != ["THM-0003"]:
        return f"a malformed row read as {broken!r}/{broken_ids!r}"
    if not movement_defects([], Standing({}), set(), unmeasurable=["THM-0003"]):
        return "an unmeasurable claim read as an unchanged one"
    return None


def check_added_theorem_is_outside(fx: Fixture) -> str | None:
    grown, _ = claim_components({"theorem": [thm("THM-0001"), thm("THM-0009")]})
    if moved_claims(fx.base, grown):
        return "an added/deleted theorem entered the movement set"
    return None


CHECKS = (
    check_well_formed_row_is_measurable,
    check_cascade_reaches_dependents,
    check_uncarried_movement_is_enforced,
    check_rereview_silences,
    check_correction_silences,
    check_unreviewed_is_silent,
    check_equality_is_silent,
    check_unfingerprintable_is_unmeasurable,
    check_added_theorem_is_outside,
)
