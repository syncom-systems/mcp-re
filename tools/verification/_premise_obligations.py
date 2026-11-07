# SPDX-License-Identifier: Apache-2.0
"""Review obligations whose OBSERVABLE discharging event has already happened — C4 — and the
list of those still open."""

from __future__ import annotations

from dataclasses import dataclass

from _premise_model import REPO_ROOT, STALE_CAUSE, is_live

#: Which key carries a toolchain's version, in the order the lock uses them.
#:
#: Read in order rather than guessed per tool: `[verus]` states a `release`, `[rust]` a
#: `channel`, the extraction container a `tag`. A resolver hard-coding one of them would
#: silently return None for the others — and None here means "the lock does not pin it",
#: which `has_come_true` treats as nothing to compare. A quiet None is how an observable
#: obligation stops being observed.
_VERSION_KEYS = ("release", "channel", "version", "revision", "tag")


def _pinned_version(toolchains: dict, tool: str) -> str | None:
    """The pinned version of one toolchain, or None if the lock does not name it."""
    entry = toolchains.get(tool)
    if isinstance(entry, dict):
        for key in _VERSION_KEYS:
            if entry.get(key):
                return str(entry[key])
    return None


@dataclass(frozen=True)
class _Observed:
    """What an observable predicate is evaluated over."""

    verification: dict
    toolchains: dict


def _toolchain_moved(entry: dict, event: dict, observed: _Observed) -> str | None:
    pinned = _pinned_version(observed.toolchains, str(event["tool"]))
    if pinned is None or pinned == str(event["from"]):
        return None
    return (
        f"{STALE_CAUSE}: {entry['id']} is held open by the pinned {event['tool']} "
        f"being {event['from']}, and the tree now pins {pinned}. The ceiling it "
        f"names may be gone; re-read the premise and discharge or restate it."
    )


def _scheme_arrived(entry: dict, event: dict, observed: _Observed) -> str | None:
    for unit in observed.verification.get("unit", []):
        if unit["id"] != str(event["unit"]):
            continue
        if any(str(e).startswith(f"{event['scheme']}://") for e in unit.get("evidence", [])):
            return (
                f"{STALE_CAUSE}: {entry['id']} stands in for {event['scheme']} evidence "
                f"on unit {event['unit']}, which now declares it. The registry is "
                f"asserting a gap the registry itself says is filled."
            )
    return None


def _site_gone(entry: dict, event: dict, observed: _Observed) -> str | None:
    path = str(event["site"]).partition("#")[0]
    if (REPO_ROOT / path).is_file():
        return None
    return (
        f"{STALE_CAUSE}: {entry['id']} is a premise about {event['site']}, and "
        f"{path} is no longer in the tree. Trusting the behaviour of something that "
        f"does not exist is a leftover, not a premise."
    )


#: How each observable predicate is evaluated, by the name a record gives it.
_OBSERVERS = {
    "toolchain-version-differs": _toolchain_moved,
    "unit-has-evidence-scheme": _scheme_arrived,
    "site-absent": _site_gone,
}


def has_come_true(entry: dict, verification: dict, toolchains: dict) -> str | None:
    """Why this obligation's observable event has ALREADY happened, or None — C4.

    Returns a sentence naming the cause, never a verdict: the caller decides what a stale
    obligation does to the build. `owner-event` always returns None, and that is the design
    rather than a gap — the gate does not guess whether an unobservable event occurred, it
    reports the obligation as open against every root that reaches it.
    """
    event = entry.get("discharging_event")
    if not isinstance(event, dict) or event.get("kind") == "owner-event":
        return None
    observe = _OBSERVERS.get(event.get("predicate"))
    if observe is None:
        return None
    return observe(entry, event, _Observed(verification, toolchains))


def _is_open_obligation(entry: dict) -> bool:
    return is_live(entry) and entry.get("premise_class") == "review-obligation"


def stale_obligations(assumptions: dict, verification: dict, toolchains: dict) -> list[str]:
    """Review obligations whose OBSERVABLE discharging event has already happened — C4.

    Not a pass, and not a silent discharge. The registry would be asserting debt the tree
    says is paid, which is the same stale-record defect `_evidence.write_bundle` records for
    the evidence bundle: a record that outlives the state it describes makes the tree look
    measured when it is not.

    Discharge is a registry EDIT, owner-reviewed like every other security-sensitive change.
    `check-assumptions`' job is not to notice a discharge; it is to make the debt impossible
    to stop seeing. `owner-event` obligations are never reported here, because nothing
    observes them — they are reported as OPEN, in the release view, against every root that
    reaches them.
    """
    problems = (
        has_come_true(entry, verification, toolchains)
        for entry in assumptions.get("assumption", [])
        if _is_open_obligation(entry)
    )
    return [problem for problem in problems if problem is not None]


def open_obligations(assumptions: dict) -> list[dict]:
    """Every live review obligation, in registry order — the release view's input (N5)."""
    return [entry for entry in assumptions.get("assumption", []) if _is_open_obligation(entry)]
