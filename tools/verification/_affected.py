# SPDX-License-Identifier: Apache-2.0
"""Which verification units a change reaches, and what a change to the platform means.

Two questions are asked about a change, and they are different questions with different
inputs, so each has one implementation and they share what they have in common:

  DECLARED REACH — `by_paths`. The units whose declared `paths` name a changed file, widened
  to every unit when the change alters what every unit is about or what every measurement
  means, then closed over prerequisite edges. Answerable at any commit from that commit's
  registry and its list of changed files, without either tree on disk. The merge-readiness
  gate requires evidence for exactly this set.

  MOVED EVIDENCE — `select-units`. The units whose fingerprint differs between two trees,
  closed over the same edges. It needs both trees measured by their own instruments, which
  is why it lives in that tool and not here.

What the two share lives here: how a declared path names a changed file (`declares`), the
prerequisite consumer closure (`consumer_closure`), and the platform path sets.
`_graph.context_closure` is a third question — which neighbours a reviewer should READ — and
carries no invalidation, so it is deliberately not this closure.
"""

from __future__ import annotations

from pathlib import PurePosixPath

import _registries
from _evidence import PREREQUISITE_KINDS
from _fingerprint import WORKSPACE_BUILD_INPUTS

#: The code that measures: a change here changes what every verdict means.
INSTRUMENT = ("tools/verification/",)

#: The workflows that run the instrument over a scope it computed.
INSTRUMENT_WORKFLOWS = (
    ".github/workflows/verification.yml",
    ".github/workflows/mutation-probe.yml",
)

#: The policy registries: a change here changes what is declared about every unit.
REGISTRIES = (f"{_registries.POLICY_RELATIVE}/",)

_GLOB = "*?["


def is_glob(declared: str) -> bool:
    return any(ch in declared for ch in _GLOB)


def declares(declared: str, changed: str) -> bool:
    """Whether the declared `paths` entry `declared` names the changed file `changed`.

    A glob entry is matched with the syntax `_boundary_crossings.expand_paths` expands it with, as a
    pattern rather than against a tree, so the answer holds for a commit that is not checked
    out. A literal entry names a file, or a directory and everything under it.
    """
    if is_glob(declared):
        return PurePosixPath(changed).full_match(declared)
    return changed == declared or changed.startswith(declared.rstrip("/") + "/")


def _consumer_index(edges: list[dict]) -> dict[str, list[str]]:
    """Each unit's consumers over a prerequisite edge."""
    consumers: dict[str, list[str]] = {}
    for edge in edges:
        if edge.get("kind") in PREREQUISITE_KINDS:
            consumers.setdefault(edge["from"], []).append(edge["to"])
    return consumers


def consumer_closure(units: set[str], edges: list[dict]) -> set[str]:
    """`units` plus every unit that consumes one of them over a prerequisite edge."""
    consumers = _consumer_index(edges)
    closure = set(units)
    frontier = list(units)
    while frontier:
        unseen = [c for c in consumers.get(frontier.pop(), ()) if c not in closure]
        closure.update(unseen)
        frontier.extend(unseen)
    return closure


def platform_change(paths) -> str | None:
    """Why a scope computed over `paths` is not trusted, or None.

    A change to the instrument, or to the workflows that run it over a computed scope, means
    the scope would be computed by the thing that changed.
    """
    hits = sorted(p for p in paths if p.startswith(INSTRUMENT + INSTRUMENT_WORKFLOWS))
    if hits:
        return f"the change touches the verification platform: {', '.join(hits[:5])}"
    return None


def _reaches_every_unit(changed: set[str]) -> bool:
    """Whether a changed file is a workspace build input, the instrument or a registry."""
    return any(c in WORKSPACE_BUILD_INPUTS or c.startswith(INSTRUMENT + REGISTRIES) for c in changed)


def _declared_by(unit: dict, changed: set[str]) -> bool:
    """Whether any of the unit's declared `paths` names a changed file."""
    return any(declares(declared, c) for declared in unit.get("paths", []) for c in changed)


def by_paths(units: list[dict], edges: list[dict], changed: set[str]) -> set[str]:
    """DECLARED REACH: the unit ids whose evidence this change can invalidate.

    Three widenings, each closing a way a change reaches a unit without touching its own
    declared paths: a workspace build input changes what EVERY unit is about; the instrument
    and the registries change what every measurement MEANS; and a prerequisite edge carries a
    producer's invalidation forward to its consumers.
    """
    if _reaches_every_unit(changed):
        return {u["id"] for u in units}
    hit = {unit["id"] for unit in units if _declared_by(unit, changed)}
    return consumer_closure(hit, edges)
