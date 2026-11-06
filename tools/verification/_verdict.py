# SPDX-License-Identifier: Apache-2.0
"""The aggregate verdict algebra over lane verdicts — ADR-MCPRE-059."""

from __future__ import annotations




#: What a single lane may declare on its `VERDICT:` line.
#:
#: Five states, because three conflated two pairs of genuinely different situations and
#: the difference is exactly where a false PASS gets in:
#:
#:   NOT_REQUIRED  the manifest asks nothing of this lane — no unit of its class exists.
#:                 Legitimate, and does NOT hold the aggregate back.
#:   PASS          executed and satisfied.
#:   FAIL          executed and not satisfied.
#:   UNAVAILABLE   required, but could not execute — tools unpinned, lane absent on this
#:                 host, container unreachable.
#:   SKIPPED       required, could have executed, deliberately not executed.
#:
#: UNAVAILABLE and SKIPPED are both "required and missing", so both force INCOMPLETE. They
#: are kept apart because the remedy differs: one is an environment to fix, the other a
#: decision to justify. Neither may ever read as success — that is the whole point of the
#: split.
LANE_VERDICTS = {"NOT_REQUIRED", "PASS", "FAIL", "UNAVAILABLE", "SKIPPED"}


#: The aggregate a run reports, derived from the lane verdicts.
AGGREGATE_VERDICTS = {"PASS", "FAIL", "INCOMPLETE"}


def aggregate_verdict(formal_verdicts, hygiene_verdicts=()) -> str:
    """Merge lane verdicts into the repository's formal verdict.

        every required formal lane PASSed            -> PASS
        any required lane FAILed                     -> FAIL
        any required formal lane absent/unavailable  -> INCOMPLETE
        no formal lane required at all               -> INCOMPLETE

    Two kinds of lane, and conflating them produces the exact false success this whole
    design exists to prevent:

      * **formal** lanes (Verus, Lean, generated-model) produce evidence. Only these can
        constitute a PASS.
      * **hygiene** lanes (manifest validation, the assumption/TCB gate) can *withhold* a
        pass by failing, but passing them proves nothing about the code. They are
        preconditions for trusting evidence, not evidence.

    So a repository with green hygiene gates and no proofs is `INCOMPLETE`. Letting the
    assumption gate's PASS carry the aggregate would mean an empty manifest reads as a
    verified repository — "exits 0 having measured nothing", one level up again.

    `NOT_REQUIRED` is excluded from the requirement set rather than counted as a pass:
    "the manifest asked nothing of Lean" and "Lean proved something" are different claims,
    and only the second is evidence. A run in which every formal lane is `NOT_REQUIRED`
    has produced no evidence and is therefore `INCOMPLETE`.

    An unrecognized verdict is INCOMPLETE — unknown is dirty (ADR-MCPRE-059 §2).
    """
    formal = list(formal_verdicts)
    hygiene = list(hygiene_verdicts)
    every = formal + hygiene
    if not set(every) <= LANE_VERDICTS:
        return "INCOMPLETE"
    # A failing precondition outranks everything: evidence gathered beside a broken
    # assumption gate is not evidence we may rely on.
    if "FAIL" in every:
        return "FAIL"
    required = [v for v in formal if v != "NOT_REQUIRED"]
    if not required:
        return "INCOMPLETE"
    if not {"UNAVAILABLE", "SKIPPED"}.isdisjoint(required + hygiene):
        return "INCOMPLETE"
    return "PASS"
