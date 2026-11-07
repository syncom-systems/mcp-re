# SPDX-License-Identifier: Apache-2.0
"""Whether a subject's correction records carry a review to the tree: the `from -> to` walk
and the reason it reports."""

from __future__ import annotations


def _walk(
    by_from: dict[str, dict], start: str, limit: int
) -> tuple[list[dict], str] | None:
    """The records reached by following `from -> to` out of `start`, and where the walk
    stops. None when it takes more steps than there are records: a cycle."""
    walked: list[dict] = []
    cursor = start
    while cursor in by_from:
        record = by_from[cursor]
        walked.append(record)
        cursor = str(record["to_fingerprint"])
        if len(walked) > limit:
            return None
    return walked, cursor


def _accepted_reason(walked: list[dict], total: int) -> str:
    ids = [c["id"] for r in walked for c in r["corrections"]]
    superseded = total - len(walked)
    return (
        f"corrected under {walked[-1]['authority']} in {len(walked)} recorded step(s), "
        f"{len(ids)} correction(s): {', '.join(ids)}"
        + (f"; {superseded} superseded record(s) off the chain" if superseded else "")
    )


def chain(
    records: list[dict], reviewed_fingerprint: str | None, current_fingerprint: str
) -> tuple[bool, str]:
    """Whether `records` carry `reviewed_fingerprint` all the way to `current_fingerprint`.

    Returns (accepted, reason). Authority comes only from the WALK: the records reached by
    following `from -> to` out of the fingerprint the review covers. A record off the walk
    authorizes nothing.

    Off the walk, a record is one of two things, and the walk decides which:

        the walk reaches the tree   the record is SUPERSEDED history: a correction the
                                    owner's later review replaced as the chain's start.
                                    Deleting it would destroy the audit trail the register
                                    exists to keep, and it cannot carry the claim anywhere,
                                    because the claim is already carried. It is accepted
                                    and counted in the reason.
        the walk stops short        the record is a DEAD ROW: it may be the next live link
                                    written against the wrong fingerprint, and it is
                                    refused with the walk.

    The second case is the one the totality rule exists for, and it is still refused. The
    first used to be refused too, which made every re-reviewed claim with a correction
    history fail the moment it moved again, its history unretirable.
    """
    if not records:
        return False, "no correction record"
    if not reviewed_fingerprint:
        return False, (
            "no specification review to correct from: a correction is a delta on a claim "
            "the owner reviewed, and there is no such claim here"
        )
    by_from = {str(r["from_fingerprint"]): r for r in records}
    if len(by_from) != len(records):
        return False, "two records start from the same fingerprint; the chain is ambiguous"
    walk = _walk(by_from, reviewed_fingerprint, len(records))
    if walk is None:
        return False, "the correction records form a cycle"
    walked, cursor = walk
    if cursor != current_fingerprint:
        return False, (
            f"the correction chain ends at {cursor[7:23]} and the tree is at "
            f"{current_fingerprint[7:23]}: the claim moved again after the last recorded "
            f"correction"
        )
    if not walked:
        return False, (
            f"no correction record starts at the reviewed fingerprint "
            f"{reviewed_fingerprint[7:23]}: every record is off the chain"
        )
    return True, _accepted_reason(walked, len(records))
