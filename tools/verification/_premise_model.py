# SPDX-License-Identifier: Apache-2.0
"""The vocabulary of the premise ontology: the premise classes, the model-registration
class, the discharging-event kinds and the closed predicate table, and the two questions
asked of an entry everywhere (is it live, is it a registration)."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Why a chain terminates — ADR-MCPRE-068 §4.2, owner Ruling 2.
PREMISE_CLASSES = ("assumed", "external-boundary", "review-obligation")

#: A registration of the prover's VOCABULARY, not a premise — r12 Ruling 39 §4.
#:
#: An `uninterp` declaration adds no axiom: every theorem that mentions it holds for every
#: interpretation. The mechanism census still counts it, so it is registered, and what it
#: denotes is given by the premise it names in `interpreted_by`. Theorem premise accounting
#: attributes the trust to that premise and never to the registration, so a registration
#: never inflates a load-bearing count. Not in `PREMISE_CLASSES`: those answer why a chain
#: terminates, and a registration terminates nothing.
MODEL_REGISTRATION = "model-registration"

#: What each kind of discharging event is observable OVER.
EVENT_KINDS = ("registry-fact", "tree-fact", "owner-event")

#: The cause a stale obligation is reported under. Named once: a cause token spelled in two
#: places is a cause a reader can grep for and miss.
STALE_CAUSE = "STALE_REVIEW_OBLIGATION"

#: The predicates each observable kind may use, and the operands each takes.
#:
#: CLOSED, and small. An open predicate vocabulary would let a record state a condition the
#: gate silently cannot evaluate, which is prose again with a table around it.
PREDICATES = {
    "registry-fact": {
        # The pinned identity of a verification toolchain moved away from the version the
        # premise was written against. A ceiling attributed to "the pinned toolchain" stops
        # being a statement about THIS tree the moment the pin changes.
        "toolchain-version-differs": ("tool", "from"),
        # A unit acquired evidence of a scheme it did not have. The premise that stood in
        # for that evidence is then describing a gap the registry says is filled.
        "unit-has-evidence-scheme": ("unit", "scheme"),
    },
    "tree-fact": {
        # The seam the premise is about is no longer in the tree. Trusting the behaviour of
        # something that does not exist is not a premise; it is a leftover.
        "site-absent": ("site",),
    },
    "owner-event": {},
}

#: The keys every `discharging_event` may carry, and the one an `owner-event` adds.
COMMON_EVENT_KEYS = {"kind"}
OWNER_EVENT_KEYS = {"statement"}


def is_live(entry: dict) -> bool:
    """Whether this premise trusts anything. A withdrawn one has an empty scope."""
    return bool(entry.get("scope"))


def is_model_registration(entry: dict) -> bool:
    """Whether this entry registers prover vocabulary rather than stating a premise."""
    return entry.get("premise_class") == MODEL_REGISTRATION
