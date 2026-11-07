#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Claim-surface gate — the published claims and the declared roots are one fact.

THE FAILURE CLASS, which is why this file exists rather than any single instance:

    Two documents that independently decide what the system promises will disagree, and
    the disagreement is invisible because each reads as authoritative on its own.

It had already happened. `verification/policy/theorems.toml` declared TWELVE
`root_theorems`; `docs/spec/security-boundary.md` §2 — the ratified positive-claim
surface, whose own text says "a claim with no root in this table is not a claim this
document makes" — carried NINE rows. THM-0091, THM-0094 and THM-0095 were established and
owner-reviewed while §4 still listed them as *in scope and not yet established*, §5
reported "Root completeness: 7 of 9" against a tree reporting 12 of 12, and §7.1 — the
moves ledger that exists so no amendment is absorbed silently — had a row for none of it.
Nothing failed. Nothing could: no control related the two surfaces.

WHAT THIS GATE DOES NOT DO, deliberately. It does not generate the claim prose. A security
consequence written for a human reader is not derivable from a theorem statement, and a §2
built by templating theorem titles would be a worse document that happened to be
consistent. The split is:

    theorem registry     root IDENTITY and MEMBERSHIP — which claims are system promises
    review records       whether the owner has reviewed the CURRENT statement of each
    boundary spec §2     the human security consequence, one per root, deliberately written
    this gate            the mapping between them, mechanically, with no third opinion

So the registry may not gain a root without the boundary gaining a claim, the boundary may
not claim what no root supports, and neither may drift while the other stands still.

WHAT IT PROVES, from SOURCE alone:

  * TOTAL       every declared root has exactly one §2 claim row.
  * SOUND       every §2 row names a declared root.
  * UNIQUE      no root is claimed twice — two rows for one root are two authorities.
  * DISJOINT    no theorem is both claimed (§2) and disclaimed (§4). A document cannot
                make and withhold the same claim.
  * NOT STALE   every claimed root's specification review covers its CURRENT fingerprint,
                OR a RECORDED ADR-MCPRE-068 Phase-1 claim correction carries it there from
                the fingerprint the owner did review. A published claim whose statement has
                moved for no recorded reason is a claim nobody has approved in its present
                form. See `tools/verification/_claim_corrections.py` for what a record must
                assert and why the chain starts at the owner's review; in short, a
                correction is a recorded DELTA on a reviewed claim, it is one-shot, and it
                does NOT make the specification-review axis fresh — release-mode
                establishment still asks for the human.
  * §4 SHAPE    the open-gap table names no declared root, and no area twice. A root that
                is a system promise is not simultaneously an unclosed gap, and a duplicated
                area row gives a reader a different answer depending which one they reach.
  * NOT MOVED   every theorem the OWNER HAS REVIEWED whose claim this branch moves is
                carried by a review at the new claim or by a recorded correction — not only
                the twelve published roots. See THE REACH below.

THE REACH, and why it is derived rather than listed. Until 2026-09-21 the staleness rule
above ranged over `declared` — the twelve §2-published roots — so a theorem was enforced if
it was published, or if it was already enforced. Nothing pulled a theorem into the enforced
set BECAUSE ITS CLAIM MOVED. Measured on one branch: a single sentence removed from
THM-0023's scope moved NINE theorems' fingerprints, five of them `critical`, and this gate
named ONE. THM-0105's own claim text moved in the same push, held by no other theorem's
closure and published as no root, and nothing in the repository would have reported it.

The published roots are still held hardest — a root with no §2 row, or a §2 row whose review
went stale, fails whether its claim moved or not. What is added is the second, derived
population: compare each theorem's claim components against the MERGE BASE with
`origin/main` and enforce over what actually moved. That set costs one `git show` of
`verification/policy/theorems.toml`, because a theorem fingerprint reads that file and
nothing else.

Three decisions inside it, each of which the obvious implementation gets wrong:

  * THE MERGE BASE, not `origin/main`'s tip. The question is *what did THIS branch move*.
    Against the tip, a claim corrected on `main` after this branch forked reads as this
    branch's movement, and the gate would demand a record from the wrong author.
  * CLAIM COMPONENTS, not the composite fingerprint. `encoding_version` participates in the
    fingerprint and is excluded here: bumping how a claim is ENCODED changes every digest
    while changing nothing a reviewer approved, and a gate that demanded 128 records for it
    would be routed around within the hour.
  * ONLY WHAT THE OWNER REVIEWED. A theorem with no specification review record has no
    approval to invalidate, so moving it breaks nothing this gate is about. Introducing an
    unreviewed theorem is release-mode establishment's question, and it asks for the human.

WHAT THE MOVEMENT HALF DOES NOT COVER, stated because a derived population reads as wider
than it is: a theorem ADDED on the branch (no prior claim to have moved) and one DELETED by
it (no current claim) are both outside it — the registry's own loader and the §2 mapping
above judge those. And when the merge base cannot be read the half is SKIPPED and the skip
is PRINTED, on `module_size_gate.py`'s precedent: a comparison that quietly no-ops when it
cannot find its baseline is this platform's own "green that measured nothing".

WHAT IT DOES NOT PROVE: that a claim's prose is *accurate*, that the evidence behind a root
is fresh, or that the argument composes. Evidence freshness is `tools/verification/review`
and it reads the attestation store, which is machine-local and gitignored — a merge-path
control cannot see it, and a gate that pretended to would be reporting one machine's state
as a property of the commit. This gate is the mapping, and says so.

Run:  python3 scripts/claim_surface_gate.py
      python3 scripts/claim_surface_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _claim_surface.cli import judge  # noqa: E402
from _claim_surface.config import (  # noqa: E402,F401
    BOUNDARY,
    COMPONENT_PROSE,
    GAP_HEADER,
    MOVEMENT_REF,
    REPO,
    SETTLED_HEADER,
    THM,
)
from _claim_surface.mapping import mapping_defects  # noqa: E402,F401
from _claim_surface.movement import (  # noqa: E402,F401
    claim_components,
    measure_movement,
    merge_base,
    moved_claims,
    movement_defects,
    theorems_at,
)
from _claim_surface.selftest import selftest  # noqa: E402,F401
from _claim_surface.spec import (  # noqa: E402,F401
    Surfaces,
    claim_rows,
    gap_rows,
    read_surfaces,
    sections,
    settled_rows,
    split_section4,
    table_rows,
)
from _claim_surface.standing import Registry, Standing, derive_registry  # noqa: E402,F401


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    return judge()


if __name__ == "__main__":
    raise SystemExit(main())
