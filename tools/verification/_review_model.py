# SPDX-License-Identifier: Apache-2.0
"""The vocabulary of `_review`: the review axes, the closed record schema, the review states
and their precedence, and the root-completeness verdicts. The only logic here is the
cause-precedence rule; the modules that derive a state import the names they need from this one."""

from __future__ import annotations

from pathlib import Path

#: The review axes, closed. A record naming anything else resolves to no axis and is
#: dropped — an unknown axis must not be counted as some default one.
AXES = {"specification", "assumption", "audit"}

#: What a subject id must look like on each axis, so a record cannot approve a theorem
#: under the assumption axis and have it read as either.
SUBJECT_PREFIX = {"specification": "THM-", "assumption": "ASM-"}

#: The record schema, CLOSED. Closed rather than filtered against a list of forbidden
#: names, because an approval bit is only one of the things a record must not carry: any
#: key outside this set is a fact this schema cannot compare, and a record carrying one
#: would be read as approving something it never described. `approved`, `status` and the
#: rest are refused by this rule, not by a second list that could drift out of step with
#: it. The repository-wide named-key scan lives in `scripts/registry_approval_gate.py`,
#: where documents are arbitrary and a closed schema is not available.
RECORD_KEYS = {
    "axis",
    "subject",
    "reviewed_fingerprint",
    "components",
    "review_digest",
    "review_components",
    "reviewer",
    "notes",
}
RECORD_REQUIRED = {"axis", "subject", "reviewed_fingerprint", "reviewer"}

#: Which moved component produces which cause. Same shape as `_graph.COMPONENT_STATE`, and
#: for the same reason: "this review is stale" without naming what moved sends the reviewer
#: to re-read everything.
COMPONENT_CAUSE = {
    "theorem_claim": "STALE_CLAIM",
    "theorem_dependencies": "STALE_DEPENDENCY_CLAIM",
    "theorem_review_requirement": "STALE_REVIEW_REQUIREMENT",
}

#: Precedence when SEVERAL components moved at once — the same device as
#: `_graph.STATE_PRECEDENCE`, and added for the same reason it exists there: the reviewer
#: should be told the most fundamental cause, not an incidental one.
#:
#: It was `sorted(causes)[0]`, which is alphabetical order, and alphabetical order happened
#: to put `STALE_CLAIM` first. That is correct by accident, not by construction: the next
#: cause anyone adds decides its own rank by its spelling, and a name beginning with
#: `STALE_A…` would mask a moved claim behind it. The tie-break has to be a decision.
#:
#: `STALE_INPUT` leads, mirroring `UNKNOWN` in `_graph`: it means a component moved that
#: this schema has no name for, so the named causes cannot be assumed complete, and the
#: reviewer knows least about exactly that case. The three named causes then run from the
#: claim itself, through the premises beneath it, to who must review it.
CAUSE_PRECEDENCE = (
    "STALE_INPUT",
    "STALE_CLAIM",
    "STALE_DEPENDENCY_CLAIM",
    "STALE_REVIEW_REQUIREMENT",
)

#: Review states. `UNREVIEWED` and `STALE_*` are both "not reviewed as it stands now", and
#: they stay apart because the remedy differs: one has never been read, the other was read
#: at something else.
UNREVIEWED = "UNREVIEWED"
REVIEWED = "REVIEWED"
UNKNOWN = "UNKNOWN"
#: A record that is out of date and cannot say what moved, because it recorded no
#: components. Distinct from the `STALE_*` causes, which can.
STALE_REVIEW = "STALE_REVIEW"

#: A review record that matches the tree, for a subject the owner-approval ledger does not
#: back as it stands (`_approvals.ledger_state`): a record is a file anyone can commit, and
#: the ledger is where the owner's signature over the text is checked.
UNBACKED = "UNBACKED"
#: A theorem whose own specification review holds while an assumption in its premise closure
#: is not reviewed and backed at its current digest.
PREMISE_UNREVIEWED = "PREMISE_UNREVIEWED"

#: A specification record that matches the claim but carries no `review_digest`: it was
#: written before the semantic axis existed, so nothing says which supporting code, tests
#: and proved symbols the reviewer read. No digest is reconstructed for it — the review
#: cannot be shown current, and reads this until the owner re-reviews.
NO_SEMANTIC_DIGEST = "NO_SEMANTIC_DIGEST"
#: A specification record whose `review_digest` no longer matches: a premise, a supporting
#: unit's source or specification, its test or probe selection, or its proved symbols moved
#: since the owner read it.
STALE_SEMANTICS = "STALE_SEMANTICS"

#: Every state this module can return. Anything not `REVIEWED` withholds REVIEW_CURRENT.
REVIEW_STATES = {
    UNREVIEWED,
    REVIEWED,
    UNKNOWN,
    STALE_REVIEW,
    "STALE_INPUT",
    UNBACKED,
    PREMISE_UNREVIEWED,
    NO_SEMANTIC_DIGEST,
    STALE_SEMANTICS,
} | set(COMPONENT_CAUSE.values())


def by_precedence(causes: set[str]) -> str:
    """The most fundamental cause among those that moved.

    An unranked cause sorts LAST rather than first: a cause nobody placed must not silently
    outrank one somebody did, and `REVIEW_STATES` plus the census in `test_theorem_review`
    keep the set from growing unnoticed.
    """
    for cause in CAUSE_PRECEDENCE:
        if cause in causes:
            return cause
    return sorted(causes)[0] if causes else "STALE_INPUT"


def review_root(repo_root: Path) -> Path:
    return repo_root / "verification" / "reviews"


#: Root-completeness verdicts. `UNDECLARED` exists so that "no system promise is stated"
#: can never be printed as good news: a repository that declares no root has nothing to be
#: complete about, and reporting PASS there would make the emptiest registry the greenest.
COMPLETE = "COMPLETE"
INCOMPLETE = "INCOMPLETE"
UNDECLARED = "UNDECLARED"
