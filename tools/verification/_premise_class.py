# SPDX-License-Identifier: Apache-2.0
"""Why an entry's `premise_class` is not usable: the per-class rules (C1-C3) and the check
that a model registration is carried by a live interpreting premise."""

from __future__ import annotations

from _premise_model import (
    COMMON_EVENT_KEYS,
    EVENT_KINDS,
    MODEL_REGISTRATION,
    OWNER_EVENT_KEYS,
    PREDICATES,
    PREMISE_CLASSES,
    is_live,
    is_model_registration,
)


def _withdrawn_problem(where: str, entry: dict, declared: object) -> str | None:
    if declared is None:
        return None
    return (
        f"{where}: withdrawn premise {entry['id']} declares `premise_class` "
        f"{declared!r}. A withdrawn assumption trusts nothing — that is what "
        f"withdrawing it meant — so typing it makes a retired premise read as a "
        f"live one."
    )


def _missing_class_problem(where: str) -> str:
    return (
        f"{where}: missing `premise_class`. Every live premise says WHY the chain "
        f"terminates without MCP-RE establishing it, from {list(PREMISE_CLASSES)} "
        f"(ADR-MCPRE-068 §7, C1). The field is not `class`: that key carries the "
        f"V0/V1/V2 tier on `[[unit]]`, and one name over two closed vocabularies in "
        f"one loader is one name meaning whichever the reader assumed."
    )


def _interpreted_problem(where: str, declared: object) -> str:
    return (
        f"{where}: `interpreted_by` on a {declared!r} premise. Only a "
        f"`{MODEL_REGISTRATION}` is given its meaning by another premise; a premise "
        f"that carries trust of its own interprets nothing."
    )


def _unknown_class_problem(where: str, declared: object) -> str:
    return (
        f"{where}: `premise_class` is {declared!r}, not one of "
        f"{list(PREMISE_CLASSES)}. `proved`, `structural`, `tested` and `measured` are "
        f"EVIDENCE classes on `[[unit]].evidence_class`: they answer how MCP-RE "
        f"establishes a proposition, which is the question a premise exists because "
        f"nobody answered (Ruling 2)."
    )


def _assumed_problem(where: str, entry: dict) -> str | None:
    extra = [k for k in ("boundary_owner", "discharging_event") if entry.get(k)]
    if not extra:
        return None
    return (
        f"{where}: `premise_class = 'assumed'` with {extra}. An assumed premise is one "
        f"nothing establishes and nothing is scheduled to discharge; a field nothing "
        f"reads is a declaration that looks like coverage. What makes it stop being "
        f"acceptable belongs in `justification`."
    )


def registration_problem(where: str, entry: dict) -> str | None:
    """A model registration names the premise that interprets it, and nothing else."""
    giver = entry.get("interpreted_by")
    if not giver or not str(giver).startswith("ASM-"):
        return (
            f"{where}: `premise_class = '{MODEL_REGISTRATION}'` requires `interpreted_by`, "
            f"the ASM id of the premise that gives the registered symbol its meaning. "
            f"Without it the trust the symbol carries is attributed to nothing."
        )
    extra = [k for k in ("boundary_owner", "discharging_event") if entry.get(k)]
    if extra:
        return (
            f"{where}: a model registration with {extra}. It trusts nothing of its own, so "
            f"it has no owner to guarantee it and no debt to discharge."
        )
    return None


def boundary_problem(where: str, entry: dict) -> str | None:
    """C2: who guarantees it, and across which interface."""
    owner = entry.get("boundary_owner")
    if not owner or not str(owner).strip():
        return (
            f"{where}: `premise_class = 'external-boundary'` requires `boundary_owner`. "
            f"\"Redis\", alone, is not an owner statement: WHAT is guaranteed, across WHICH "
            f"interface, under WHICH configuration is (C2)."
        )
    if entry.get("discharging_event"):
        return (
            f"{where}: an external-boundary premise carries no `discharging_event`. It is "
            f"not discharged BY US, and scheduling an event for it would record a debt "
            f"nobody in this repository owes."
        )
    if "://" in str(owner) or len(str(owner).split()) < 3:
        return (
            f"{where}: `boundary_owner` is {owner!r}, which names a thing rather than a "
            f"guarantee. State the owner, the interface, and what is guaranteed across it."
        )
    return None


def _owner_event_problem(where: str, event: dict) -> str | None:
    unknown = set(event) - (COMMON_EVENT_KEYS | OWNER_EVENT_KEYS)
    if unknown:
        return (
            f"{where}: `discharging_event` has unknown key(s) {sorted(unknown)} "
            f"for kind 'owner-event'"
        )
    if not str(event.get("statement", "")).strip():
        return (
            f"{where}: an `owner-event` states what the owner is watching for. It is the "
            f"one kind nothing observes, so the statement is the whole record of it."
        )
    return None


def _predicate_problem(where: str, kind: str, event: dict) -> str | None:
    predicate = event.get("predicate")
    table = PREDICATES[kind]
    if predicate not in table:
        return (
            f"{where}: `discharging_event.predicate` is {predicate!r}; kind {kind!r} admits "
            f"{sorted(table)}. The vocabulary is CLOSED: an open one would let a record "
            f"state a condition the gate silently cannot evaluate."
        )
    allowed = COMMON_EVENT_KEYS | {"predicate"} | set(table[predicate])
    unknown = set(event) - allowed
    if unknown:
        return (
            f"{where}: `discharging_event` has unknown key(s) {sorted(unknown)} "
            f"for {predicate!r}"
        )
    missing = [operand for operand in table[predicate] if not event.get(operand)]
    if missing:
        return f"{where}: `discharging_event` for {predicate!r} is missing {missing}"
    return None


def event_problem(where: str, entry: dict) -> str | None:
    """C3: the discharging event is a tagged record from a closed set, never a sentence."""
    event = entry.get("discharging_event")
    if not isinstance(event, dict):
        return (
            f"{where}: `premise_class = 'review-obligation'` requires a `discharging_event` "
            f"TABLE. A sentence cannot be evaluated, and a discharge condition the gate "
            f"cannot read is the prose this field replaces (C3, C5: `review_requirement` "
            f"keeps the human review rule; the gate ignores prose for discharge)."
        )
    if entry.get("boundary_owner"):
        return (
            f"{where}: a review-obligation carries no `boundary_owner`. If an owner outside "
            f"MCP-RE guarantees it, the premise is an external boundary and is not our debt."
        )
    kind = event.get("kind")
    if kind not in EVENT_KINDS:
        return f"{where}: `discharging_event.kind` is {kind!r}, not one of {list(EVENT_KINDS)}."
    if kind == "owner-event":
        return _owner_event_problem(where, event)
    return _predicate_problem(where, kind, event)


#: The rule for each declared class, after the checks every live premise shares.
_CLASS_RULES = {
    "assumed": _assumed_problem,
    "external-boundary": boundary_problem,
    "review-obligation": event_problem,
}


def class_problem(where: str, entry: dict, live: bool) -> str | None:
    """Why this entry's `premise_class` is not usable, or None."""
    declared = entry.get("premise_class")
    if not live:
        return _withdrawn_problem(where, entry, declared)
    if declared is None:
        return _missing_class_problem(where)
    if declared == MODEL_REGISTRATION:
        return registration_problem(where, entry)
    if entry.get("interpreted_by"):
        return _interpreted_problem(where, declared)
    if declared not in PREMISE_CLASSES:
        return _unknown_class_problem(where, declared)
    return _CLASS_RULES[declared](where, entry)


def _unusable_interpreter(giver: dict | None) -> bool:
    return giver is None or not is_live(giver) or is_model_registration(giver)


def _registration_defect(entry: dict, by_id: dict[str, dict]) -> str | None:
    giver = by_id.get(str(entry.get("interpreted_by")))
    if giver is None or _unusable_interpreter(giver):
        return (
            f"{entry['id']}: `interpreted_by` {entry.get('interpreted_by')!r} is not a "
            f"live premise. A registration's meaning must come from one."
        )
    units = {str(t) for t in entry.get("scope", []) if str(t).startswith("unit://")}
    missing = sorted(units - {str(t) for t in giver.get("scope", [])})
    if missing:
        return (
            f"{entry['id']}: registered on {missing}, which its interpreter "
            f"{giver['id']} does not reach. The trust it is credited with would be "
            f"carried by nothing there."
        )
    return None


def registration_problems(assumptions: dict) -> list[str]:
    """Registrations whose interpreting premise does not carry their trust everywhere.

    Accounting drops a registration from every closure on the strength of its interpreter
    being there instead. That is only true where the interpreter is LIVE, is itself a
    premise, and is scoped to every unit the registration is: a registration on a unit its
    interpreter does not reach would leave that unit's premise closure silently short.
    """
    by_id = {entry["id"]: entry for entry in assumptions.get("assumption", [])}
    defects = (
        _registration_defect(entry, by_id)
        for entry in assumptions.get("assumption", [])
        if is_model_registration(entry)
    )
    return [defect for defect in defects if defect is not None]
