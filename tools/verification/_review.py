# SPDX-License-Identifier: Apache-2.0
"""Human review as evidence about a fingerprint — ADR-MCPRE-059 §14.7.

An approval is never a field of the object approved. It is a record that says *which
fingerprint* was reviewed, stored beside the thing it reviews and compared against the
fingerprint of the tree as it stands. Freshness of a review is therefore derived exactly as
proof freshness is derived, and there is nothing for a reviewer to remember to update:

    formal evidence          measured_fingerprint  = F   (attestation, `_evidence`)
    specification review     reviewed_fingerprint  = F   (theorem fingerprint)
                             review_digest         = R   (semantic evidence digest)
    assumption review        reviewed_fingerprint  = A   (assumption entry digest)
    local security audit     audited_fingerprint   = F   (unit fingerprint)

Four axes, kept apart. A single green/red bit would let a passing prover answer for an
unreviewed specification, which is the substitution this whole layer exists to refuse.

A specification review names TWO digests. `reviewed_fingerprint` is the claim surface —
statement, consequence, scope, dependency claims, review requirement — and is what the
claim-correction chain is about. `review_digest` (`_fingerprint.review_digest`) is what the
owner read the claim AGAINST: its premises, and the semantic inputs of every supporting
unit — source and specifications, the tests and probes selected, the proved and extracted
symbols. Ruling 35 §3 splits the theorem's verdict on exactly that line:

    REVIEW_CURRENT        claim, premises and semantic evidence are what the owner read
    EVIDENCE_ESTABLISHED  every supporting unit is FRESH: a run vouches for its full
                          fingerprint, toolchain, lane identities and policy included
    CURRENTLY_VERIFIED    both, and every theorem it depends on is currently verified

A toolchain or policy change makes evidence stale without asking for a re-read; an edit to
supporting source asks for both.

## Why these records are source, and attestations are not

`.verification/` is gitignored: every attestation in it is re-derivable by re-running a
lane. A human approval is not re-derivable — nothing CI can run reproduces a person having
read a claim. Gitignoring it would make the axis permanently `UNREVIEWED` on every clone,
and an axis that can never be satisfied is an axis that gets routed around.

So review records live in `verification/reviews/`, in the tree, and approving is a commit.
That is the same trust model `assumptions.toml` already uses for owner ratification: the
audit trail is the history, and the record names a fingerprint, so an approval that does not
match the tree announces itself rather than passing quietly.

This module also derives the second, separate property ADR-MCPRE-059 §28.8 defines: root
completeness. Freshness asks whether the registry still describes the tree; completeness
asks whether the claims ratified as system promises are closed. Neither implies the other,
and `root_completeness` is kept out of `theorem_assurance` so the two can never be reported
as one number.

Fail-closed everywhere. Missing record, unparsable record, unknown axis, a component the
current schema cannot compare — every one is unreviewed or dirty. There is no path here
from "I could not establish that this was reviewed" to `REVIEWED`.
"""

from __future__ import annotations

from _review_assurance import Basis
from _review_assurance import theorem_assurance
from _review_model import (
    AXES,
    CAUSE_PRECEDENCE,
    COMPLETE,
    COMPONENT_CAUSE,
    INCOMPLETE,
    NO_SEMANTIC_DIGEST,
    PREMISE_UNREVIEWED,
    REVIEW_STATES,
    REVIEWED,
    STALE_REVIEW,
    STALE_SEMANTICS,
    UNBACKED,
    UNDECLARED,
    UNKNOWN,
    UNREVIEWED,
    by_precedence as _by_precedence,
    review_root,
)
from _review_records import load_reviews, valid as _valid
from _review_roots import closure_satisfied, root_completeness
from _review_state import (
    assumption_review_state,
    backed_review_state,
    derive_review_state,
    semantic_review_state,
)

__all__ = [
    "AXES",
    "Basis",
    "CAUSE_PRECEDENCE",
    "COMPLETE",
    "COMPONENT_CAUSE",
    "INCOMPLETE",
    "NO_SEMANTIC_DIGEST",
    "PREMISE_UNREVIEWED",
    "REVIEW_STATES",
    "REVIEWED",
    "STALE_REVIEW",
    "STALE_SEMANTICS",
    "UNBACKED",
    "UNDECLARED",
    "UNKNOWN",
    "UNREVIEWED",
    "_by_precedence",
    "_valid",
    "assumption_review_state",
    "backed_review_state",
    "closure_satisfied",
    "derive_review_state",
    "load_reviews",
    "review_root",
    "root_completeness",
    "semantic_review_state",
    "theorem_assurance",
]
