# SPDX-License-Identifier: Apache-2.0
"""The ADR-MCPRE-068 premise ontology — why an assurance chain TERMINATES.

ONE authority over one fact, and it is deliberately not the evidence-class fact.
`_evidence_class` answers *how does MCP-RE establish this proposition?* for a unit; this
module answers *why does this chain end without MCP-RE establishing it?* for an assumption.
Owner Ruling 2 split them because a unit is never classified by the fact that it sits in
front of something external: our Redis wrapper's semantics are TESTED or PROVED, and Redis
command atomicity is an EXTERNAL BOUNDARY.

THREE CLASSES, BECAUSE THEY ANSWER THREE DIFFERENT QUESTIONS
------------------------------------------------------------

*Will this ever be discharged?*

  `assumed`             No, and that is accepted.
  `external-boundary`   Not by us — an owner outside MCP-RE guarantees it.
  `review-obligation`   Yes, at a named event.

Collapsing them — 47 records with one shape, which is where this started — makes the only
question anybody actually asks unanswerable: **which Critical or High root ultimately rests
on something we merely assume?** An external-boundary premise under a Critical root is a
supply-chain statement. An open review obligation under the same root is a DEBT. They must
not read alike.

THE DISCHARGING EVENT IS A TAGGED PREDICATE, NEVER PROSE (C3)
--------------------------------------------------------------

A `review-obligation` says a human must read this again at a named event, so the event has
to be something other than a sentence. Three kinds, and the third is the honest residue:

  `registry-fact`  observable over the policy TOMLs
  `tree-fact`      observable over the source tree at the current fingerprint
  `owner-event`    observable by NOTHING. The gate never guesses whether it happened.

AND AN OBSERVABLE EVENT THAT HAS COME TRUE IS A FAIL (C4)
----------------------------------------------------------

Not a pass, and not a silent discharge. A record that outlives the state it describes makes
the tree look measured when it is not — the same defect `_evidence.write_bundle` records for
the evidence bundle, where the file described the last run rather than the last successful
one. Discharge is a registry EDIT, owner-reviewed like every other security-sensitive
change. The gate's job is not to notice discharge; it is to make the debt impossible to stop
seeing.

WHY A WITHDRAWN RECORD CARRIES NO CLASS
----------------------------------------

`premise_class` is required of every LIVE premise and refused on a withdrawn one. A
withdrawn assumption trusts nothing — that is what withdrawing it meant — so typing it would
make a retired premise read as a live one. `_assumptions._require_boundary_edge` already draws
the line in exactly that place, by exactly that argument, and liveness is the same test
there: a non-empty `scope`.

Stdlib only, like the rest of this layer.
"""

from __future__ import annotations

from _premise_class import class_problem, registration_problems
from _premise_model import (
    EVENT_KINDS,
    MODEL_REGISTRATION,
    PREDICATES,
    PREMISE_CLASSES,
    REPO_ROOT,
    STALE_CAUSE,
    is_live,
    is_model_registration,
)
from _premise_obligations import has_come_true, open_obligations, stale_obligations
from _premise_roots import roots_reaching_premises

__all__ = [
    "EVENT_KINDS",
    "MODEL_REGISTRATION",
    "PREDICATES",
    "PREMISE_CLASSES",
    "REPO_ROOT",
    "STALE_CAUSE",
    "class_problem",
    "has_come_true",
    "is_live",
    "is_model_registration",
    "open_obligations",
    "registration_problems",
    "roots_reaching_premises",
    "stale_obligations",
]
