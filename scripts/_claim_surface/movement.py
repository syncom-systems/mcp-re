# SPDX-License-Identifier: Apache-2.0
"""The derived half: which theorems' claims this branch moved against its merge base."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from _claim_surface.config import COMPONENT_PROSE, MOVEMENT_REF, REPO
from _claim_surface.standing import Registry, Standing

import _registries  # noqa: E402
from _fingerprint import fingerprint_theorem  # noqa: E402
from _manifest import ManifestError  # noqa: E402

Moved = list[tuple[str, list[str]]]


@dataclass(frozen=True)
class Movement:
    """The movement half's verdict: the line it prints and the defects it found."""

    note: str
    defects: list[str]


def merge_base(ref: str = MOVEMENT_REF) -> str | None:
    """The commit this branch forked from `ref`, or `None` when it cannot be determined.

    Deliberately not `ref` itself. A claim corrected on `main` after this branch forked is
    not this branch's movement, and a gate that attributed it here would demand a record
    from an author who changed nothing.
    """
    try:
        out = subprocess.run(
            ["git", "merge-base", "HEAD", ref],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001 - any git failure is the same answer here
        return None
    return out or None


def theorems_at(commit: str) -> dict | None:
    """`theorems.toml` as of `commit`, parsed and NOT validated.

    Validation is deliberately skipped. `load_theorems` enforces TODAY's schema, and the
    baseline is a tree that was legal under whatever schema it shipped with; running the
    current validator over it would turn a legitimate schema change into a gate failure
    about a commit nobody can now edit. What is needed here is only what the claim digests
    read, and those are fields, not invariants.
    """
    try:
        text = _registries.text_at("theorems", commit, REPO)
        return None if text is None else _registries.parse(text, f"{commit}:theorems.toml")
    except ManifestError:
        return None


def claim_components(doc: dict) -> tuple[dict[str, dict], list[str]]:
    """`(per-theorem claim components, ids that could not be measured)`.

    `encoding_version` is dropped: it certifies how a claim is encoded, not what it says.
    A row this code cannot fingerprint is RETURNED as unmeasurable rather than skipped —
    a theorem silently absent from one side of a comparison is a theorem the comparison
    reports as unmoved, which is the failure this whole gate is named after.
    """
    measured: dict[str, dict] = {}
    unmeasurable: list[str] = []
    for row in doc.get("theorem", []):
        theorem = row.get("id")
        if not theorem:
            continue
        try:
            components = dict(fingerprint_theorem(row, doc)["components"])
        except Exception:  # noqa: BLE001 - a row missing a claim field is unmeasurable, not equal
            unmeasurable.append(theorem)
            continue
        components.pop("encoding_version", None)
        components.pop("theorem_id", None)
        measured[theorem] = components
    return measured, sorted(unmeasurable)


def moved_claims(before: dict[str, dict], after: dict[str, dict]) -> Moved:
    """`(theorem, which components moved)` for every theorem present on BOTH sides.

    Present on both, because the two asymmetric cases are other controls' propositions and
    answering them here would be this gate holding a second opinion: a theorem added on the
    branch has no prior claim to have moved, and one deleted by it has no current claim for
    a review to be about.
    """
    moved = []
    for theorem in sorted(set(before) & set(after)):
        which = sorted(k for k in set(before[theorem]) | set(after[theorem])
                       if before[theorem].get(k) != after[theorem].get(k))
        if which:
            moved.append((theorem, which))
    return moved


def movement_defects(
    moved: Moved,
    standing: Standing,
    reviewed_subjects: set[str],
    unmeasurable: list[str] | None = None,
) -> list[str]:
    """Every moved claim the owner had reviewed and nothing carries to where it now stands."""
    defects: list[str] = []
    for theorem, which in moved:
        if theorem not in reviewed_subjects:
            # No approval exists, so none was invalidated. Establishing an unreviewed
            # theorem is release mode's question and it asks for the human.
            continue
        verdict = standing.unreviewed(theorem)
        if verdict is None:
            continue
        state, reason, why = verdict
        parts = ", ".join(COMPONENT_PROSE.get(k, k) for k in which)
        defects.append(
            f"{theorem}'s claim moved on this branch ({parts}) and its specification "
            f"review is {state}: {reason}. The owner approved a different claim, and "
            f"nothing carries the approval to this one: {why}. This theorem is not a "
            f"published root — it is enforced because its claim MOVED, which is the "
            f"population a silent cascade hides in."
        )
    for theorem in unmeasurable or []:
        defects.append(
            f"{theorem} could not be fingerprinted on one side of the comparison, so this "
            f"gate cannot tell whether its claim moved. An unmeasurable claim must not "
            f"read as an unchanged one."
        )
    return defects


def _skipped(base: str | None) -> Movement:
    # PRINTED, never inferred from silence. A comparison that no-ops when it cannot find
    # its baseline is this platform's own "green that measured nothing", and the one edit
    # that disables it must not be the one edit nothing reports.
    return Movement(
        f"claim-movement half SKIPPED: no readable `verification/policy/theorems.toml` "
        f"at the merge base with {MOVEMENT_REF}"
        + (f" ({base[:12]})" if base else " (no merge base)")
        + ". Claim movement was NOT measured on this run.",
        [],
    )


def measure_movement(registry: Registry) -> Movement:
    """Compare every theorem's claim components against the merge base and enforce over what moved.

    Everything in the mapping ranges over the published roots; this ranges over what this
    branch actually moved, which is the population SF-009 measured the gate missing by
    eight theorems out of nine.
    """
    base = merge_base()
    baseline_doc = theorems_at(base) if base else None
    if baseline_doc is None:
        return _skipped(base)
    before, unmeasurable_before = claim_components(baseline_doc)
    after, unmeasurable_after = claim_components(
        {"theorem": registry.theorems.get("theorem", [])}
    )
    moved = moved_claims(before, after)
    defects = movement_defects(
        moved,
        registry.standing,
        registry.reviewed_subjects,
        sorted(set(unmeasurable_before) | set(unmeasurable_after)),
    )
    compared = len(set(before) & set(after))
    return Movement(
        f"{compared} theorem(s) compared against the merge base with {MOVEMENT_REF} "
        f"({base[:12]}), {len(moved)} moved",
        defects,
    )
