# SPDX-License-Identifier: Apache-2.0
"""Loading and validating the toolchain lock, and naming the identities it leaves unpinned."""

from __future__ import annotations

from collections.abc import Iterable

from _extraction_artifact import record_problems as artifact_record_problems
from _extraction_identity import identity_problems
from _registries import ManifestError
from _toolchains import unresolved_pins
import _toolchains


def load_toolchains() -> dict:
    """Load and validate the toolchain lock."""
    doc = _toolchains.load()
    # The extraction container's identity is COMPUTABLE from the inputs recorded beside it,
    # so it is computed here rather than trusted. Validating in the loader binds every
    # consumer at once — the gate, the Lean lane, the graph — instead of one script
    # remembering to ask.
    for problem in identity_problems(doc):
        raise ManifestError(problem)
    # The same class of question one level down: not *which* environment the pin names, but
    # whether the record says which preserved BYTES carry it. A lock that omits that cannot
    # be checked against the store at all, so it is refused here rather than at whichever
    # consumer happens to look first.
    for problem in artifact_record_problems(doc):
        raise ManifestError(problem)
    return doc


def _is_absent(toolchains: dict, head: str, tail: str) -> bool:
    """The lock has no table for `head`, or no sub-table `tail` inside it."""
    entry = toolchains.get(head)
    if not isinstance(entry, dict):
        return True
    return bool(tail) and not isinstance(entry.get(tail), dict)


def unpinned_identities(toolchains: dict, required: Iterable[str]) -> dict[str, str]:
    """Each required identity that is not resolved, mapped to WHY it is not.

    R9-C069. `unresolved_pins` answers over the tables the lock CONTAINS, so it can only
    report an identity someone wrote down and marked `unresolved`. Deleting the table
    instead removed the identity from its answer entirely, and a lane computing
    `REQUIRED & unresolved_pins(...)` then found nothing missing and ran — with `[rust]` or
    `[verus.z3]` gone from the lock, against whatever the environment supplied. The
    strongest way to unpin a tool was to stop mentioning it.

    Absence and `state = "unresolved"` are the same fact about the tool — its identity is
    unknown, and unknown is dirty — so both are returned and both are disqualifying. They
    are returned with their reason rather than as one list because the REMEDY differs and
    naming the wrong one sends the reader nowhere: an unresolved pin is resolved by
    installing the tool and recording what was installed, while an absent one is a lock
    that does not know the tool exists and is repaired by declaring it. Collapsing them
    would trade one unreadable message for another.

    `required` names dotted paths exactly as `unresolved_pins` reports them, so
    `verus.z3` asks about the sub-table and `verus` about its parent.
    """
    out: dict[str, str] = {}
    unresolved = set(unresolved_pins(toolchains))
    for name in required:
        head, _, tail = name.partition(".")
        if _is_absent(toolchains, head, tail):
            out[name] = "absent"
        elif name in unresolved:
            out[name] = "unresolved"
    return dict(sorted(out.items()))
