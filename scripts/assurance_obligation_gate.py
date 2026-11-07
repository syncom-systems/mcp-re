#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The N1 obligation ratchet — ADR-MCPRE-068 §9.4, Phase 0E.

N1: any proposition classified `tested` whose EFFECTIVE consequence severity is Medium,
High or Critical must name a registered falsifier attacking its production property.
Switching that on against a tree that predates the rule would have meant discharging 63
obligations in one change, so the residue is recorded in
`config/assurance-obligation-debt.toml` and this gate holds it.

WHAT MAKES IT A RATCHET RATHER THAN A WAIVER, and every clause below is one of the four
mechanical consequences the ratification attached to the registry:

    a unit that OWES and is not registered      -> FAIL. The registry is closed to new
                                                   work: an obligation that did not exist
                                                   at the baseline is discharged or fails.
    a registered unit that no longer owes       -> FAIL until the row is removed. A dead
                                                   row hides the next live one, the same
                                                   rule `merge_path_gate.py` applies to a
                                                   dead `off_merge_path`.
    a row whose effective severity has MOVED    -> FAIL. The obligation is not the one the
                                                   row records, so the row does not cover
                                                   it. Raising severity is "materially
                                                   changed" and may not buy a new entry.
    the registry GREW against origin/main      -> FAIL. It may only shrink, except by
                                                   SUCCESSION (below), the one way a
                                                   row count may rise.
    a status returning to `unreviewed`          -> FAIL. The lifecycle is one-way.
    a reviewed row with no live `review_ref`    -> FAIL. A completed review points at a
                                                   record, not at a memory of one.
    origin/main unreadable                      -> FAIL. The shrink-only and one-way rules
                                                   compared nothing.

SUCCESSION — the one way a row count may rise, and why it is not a loophole.

ADR-MCPRE-068 Phase 1 decomposes a root's one wide proposition into the several narrow
propositions it was always the conjunction of. A wide `tested` unit that OWED a falsifier
becomes several narrow `tested` units that owe one each. Under the rules above that is
indistinguishable from new work: the predecessor's row goes dead and every successor is an
unregistered owing unit. Phase 1 could then land no decomposition of an obligated
proposition at all — the ratchet built to stop obligations APPEARING would be stopping them
from being stated more precisely, which is the opposite of its purpose.

So a row may carry `succeeds` and `decomposition_ref`, and five things must hold together:

    the row is NOT already in the base registry        succession authorizes an ADDITION;
                                                       once the row is in the base it is an
                                                       ordinary row and the fields are
                                                       provenance
    the predecessor is a row in the BASE registry      succession refines an obligation that
                                                       already existed; it cannot invent one
    the predecessor is gone from the registry AND      the wide proposition no longer exists
    from the measured population                       or no longer owes. One that still
                                                       owes keeps its own row and succeeds
                                                       nothing
    every successor's effective severity is at most    a decomposition may not RAISE what is
    the predecessor's                                  at stake
    every successor unit's `paths` are a SUBSET of     the obligation is refined over the
    the predecessor's paths at the base                 same production code. New code cannot
                                                       ride a succession
    `decomposition_ref` names a file this tree holds   the decomposition points at its record
                                                       rather than at a memory of one

ONE AUTHORIZATION BUYS ONE TRANSITION, by the mechanism the module-size registry's
`growth_ref` uses: after merge the predecessor is no longer in the base registry, so a later
row naming it fails the first clause. A spent succession matches nothing.

AND THE MERGE IS WHAT SPENDS IT, which is why succession is validated only for rows the base
does NOT already hold. Once a successor row is in the base registry it is an ordinary
pre-existing row; its `succeeds` and `decomposition_ref` stay as PROVENANCE — a reader of the
registry can still see where the obligation came from — but they authorize nothing, because
there is nothing left to authorize. Validating them again would fail every merged
decomposition forever, on the strength of a predecessor its own merge removed. That is not
the ratchet working; it is the ratchet refusing the state it just created.

Succession discharges NOTHING. Successor rows are ordinary open obligations, INCOMPLETE like
every other row, bounding the same production code measured more finely.

WHAT IT DELIBERATELY DOES NOT DO. It does not make a registered obligation satisfied. Rows
stay INCOMPLETE, `review` prints them as open obligations, and an incomplete proposition
does not satisfy a root assurance dependency. The registry bounds the population and
records what closing a row would mean; it never subtracts from the obligation.

Run:  python3 scripts/assurance_obligation_gate.py
      python3 scripts/assurance_obligation_gate.py --selftest
      python3 scripts/assurance_obligation_gate.py --base origin/main
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _assurance_obligation.config import (  # noqa: E402,F401
    REGISTRY,
    REGISTRY_REL,
    REPO,
    REVIEWED,
    STATUSES,
    UNITS_REL,
)
from _assurance_obligation.cli import main as run  # noqa: E402
from _assurance_obligation.defects import defects  # noqa: E402,F401
from _assurance_obligation.registry import (  # noqa: E402,F401
    SCHEMA,
    base_unit_paths,
    current_unit_paths,
    load_registry,
    obligations,
    owing,
)
from _assurance_obligation.selftest import selftest  # noqa: E402,F401
from _assurance_obligation.succession import Basis, succession_defects  # noqa: E402,F401


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    return run(__doc__.splitlines()[0])


if __name__ == "__main__":
    raise SystemExit(main())
