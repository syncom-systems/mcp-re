# SPDX-License-Identifier: Apache-2.0
"""Clause 12 (THM-0081): every production refusal is inside the exchange lifecycle."""

from __future__ import annotations

import re

from _refusal_provenance.config import DECLARED_TRANSPORT_REFUSAL_SITES, SERVED_JSON, TRANSPORT
from _refusal_provenance.sources import body_of


def _minted_text(serving: str) -> tuple[str, list[str]]:
    """The serving text with the one exempt wrapper removed, and a problem if it is gone."""
    wrapper = body_of(serving, "served")
    if not wrapper:
        return serving, [
            "`served` is not in the serving subtree — the one wrapper clause 12a exempts is "
            "gone, so the scope has moved rather than the property changed"
        ]
    return serving.replace(wrapper, "", 1), []


def _mints_response(line: str) -> bool:
    if "->" in line or line.lstrip().startswith("//"):
        return False
    return bool(re.search(r"ServedHttpResponse\s*\{", line)) or SERVED_JSON in line


def minted_problems(serving: str) -> list[str]:
    """12a. the serving subtree mints no response of its own."""
    minted, problems = _minted_text(serving)
    problems += [
        f"the serving path mints a response outside `served`: {line.strip()!r} — a "
        f"refusal built at the exit is not inside the exchange lifecycle (THM-0081)"
        for line in minted.split("\n")
        if _mints_response(line)
    ]
    return problems


def handle_problems(serving: str) -> list[str]:
    """12b. `handle` answers only through its stages."""
    handle = body_of(serving, "handle")
    if not handle:
        return ["`handle` not found in the serving path"]
    problems: list[str] = []
    arms = re.findall(r"Err\((\w+)\)\s*=>\s*return\s+(\w+)\s*,", handle)
    if len(arms) != handle.count("Err("):
        problems.append(
            "an `Err` arm in `handle` does something other than return the binding its "
            "stage produced — an exit that builds its own answer is outside the "
            "lifecycle (THM-0081)"
        )
    problems += [
        f"`handle` returns {returned!r} for an `Err({bound})` arm — the answer "
        f"served is not the one the stage produced"
        for bound, returned in arms
        if bound != returned
    ]
    return problems


def transport_problems(callers: set[str], transport: str) -> list[str]:
    """12c. the pre-exchange transport refusals are exactly the declared set."""
    problems: list[str] = []
    if callers != DECLARED_TRANSPORT_REFUSAL_SITES:
        problems.append(
            f"the pre-exchange refusal sites are {sorted(callers)}, declared "
            f"{sorted(DECLARED_TRANSPORT_REFUSAL_SITES)} — an undeclared site is a refusal "
            f"reached with no exchange to place it in (THM-0081)"
        )
    if SERVED_JSON in transport and "handler(" not in transport:
        problems.append(
            f"{TRANSPORT}: the declared transport refusal no longer sits ahead of the "
            f"handler, so it is not established that it is reached before an exchange exists"
        )
    return problems


def disposition_problems(serving: str) -> list[str]:
    """12d. the retry contract is derived from the machine, not chosen at the exit."""
    disposition = body_of(serving, "disposition")
    if not disposition:
        return ["`disposition` not found — the retry contract has no derivation"]
    problems: list[str] = []
    if "retry_semantics()" not in disposition:
        problems.append(
            "`disposition` does not read `retry_semantics()` — a refusal's retry "
            "contract would be chosen at the exit rather than derived from the exchange"
        )
    if re.search(r"^\s*_\s*=>", disposition, re.M):
        problems.append(
            "`disposition` has a wildcard arm — a new machine consequence would inherit "
            "a retry contract instead of naming one"
        )
    return problems
