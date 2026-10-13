# SPDX-License-Identifier: Apache-2.0
"""The mutation-probe registry, `verification/policy/mutation-probes.toml`, and what a
probe's sites resolve to.

The lane (`verify-mutations`) and the reference gate (`check-registries`) ask the same two
questions of a probe: is the record well-formed, and does every site it weakens identify
exactly one place in the tree. One answer for both, here, so a probe the gate accepts is a
probe the lane can apply.

Stdlib only.
"""

from __future__ import annotations

from pathlib import Path

from _registries import REPO_ROOT, ManifestError, document

_OPTIONAL_PROBE_KEYS = {"note", "theorem", "also"}

_PROBE_KEYS = {
    "id",
    "unit",
    "theorem",
    "conjunct",
    "path",
    "anchor",
    "weakening",
    "expect_red",
    "note",
    "also",
}

#: The keys an `also` entry carries: one further site of the SAME proposition.
#:
#: DEFENCE IN DEPTH IS WHY THIS EXISTS, and it is deliberately narrow. Where two or more
#: independent sites each enforce the WHOLE proposition, removing any one of them leaves every
#: declared control green -- so a one-anchor probe measures nothing and the lane reports the
#: conjunct as unprotected, which is false. The weakening that falsifies such a proposition has
#: to remove the COMPLETE carrying set, atomically.
#:
#: This is NOT a mutation language. There is no ordering, no conditional, no expression over
#: sites: an `also` entry is another `(path, anchor, weakening)` triple held to exactly the same
#: single-site rule as the primary one, and every site is applied before the battery runs and
#: reverted after it. A probe using it states that these sites TOGETHER carry one conjunct.
#:
#: COMPOSITION MUST NOT USE IT. Where two checks each refuse a shape the other admits, they are
#: two conjuncts and each takes its own probe -- weakening both at once would report one
#: discharge for two propositions and hide which of them a battery covers.
_ALSO_KEYS = {"path", "anchor", "weakening"}


def load_probes(root: Path = REPO_ROOT) -> list[dict]:
    """The registry, validated strictly — an unknown key is a failure, not an ignored field.

    Same rule as every other manifest here: a mistyped security declaration must not read
    as an absent one.
    """
    probes = document("mutation-probes", root).get("probe", [])
    seen: set[str] = set()
    for index, probe in enumerate(probes):
        where = f"mutation-probes.toml [[probe]] #{index + 1}"
        unknown = set(probe) - _PROBE_KEYS
        if unknown:
            raise ManifestError(f"{where}: unknown key(s) {sorted(unknown)}")
        missing = _PROBE_KEYS - _OPTIONAL_PROBE_KEYS - set(probe)
        if missing:
            raise ManifestError(f"{where}: missing required key(s) {sorted(missing)}")
        if probe["id"] in seen:
            raise ManifestError(f"{where}: duplicate probe id {probe['id']!r}")
        seen.add(probe["id"])
        if not probe["expect_red"]:
            raise ManifestError(
                f"{where}: `expect_red` is empty. A probe that expects no control to fail "
                f"asserts nothing; it would pass over an unprotected conjunct."
            )
        for position, also in enumerate(probe.get("also", [])):
            at = f"{where} `also` #{position + 1}"
            unknown = set(also) - _ALSO_KEYS
            if unknown:
                raise ManifestError(f"{at}: unknown key(s) {sorted(unknown)}")
            absent = _ALSO_KEYS - set(also)
            if absent:
                raise ManifestError(f"{at}: missing required key(s) {sorted(absent)}")
        for position, site in enumerate([probe, *probe.get("also", [])]):
            if site["anchor"] == site["weakening"]:
                raise ManifestError(
                    f"{where}: site #{position + 1} weakens its anchor to itself. A probe that "
                    f"applies no weakening reports whatever the battery does normally."
                )
        if len(set(sites(probe))) != len(sites(probe)):
            raise ManifestError(
                f"{where}: two sites name the same (path, anchor). A probe that weakens one "
                f"site twice weakens one site, and would report a compound falsifier over a "
                f"carrying set it never removed."
            )
    return probes


def sites(probe: dict) -> list[tuple[str, str]]:
    """Every `(path, anchor)` the probe weakens, its primary site first."""
    return [(probe["path"], probe["anchor"])] + [
        (also["path"], also["anchor"]) for also in probe.get("also", [])
    ]


def weaken(tree: Path, probe: dict, where: str) -> dict[str, tuple[str, str]]:
    """Each file the probe weakens under `tree`, as `(original, weakened)` text.

    Each anchor must identify exactly one site. Two matches is as much a failure as none:
    the lane could not say which check it broke, so whatever went red proves nothing about
    the conjunct named.

    Every site resolves before anything is returned, so a caller that writes the result
    applies the whole carrying set or none of it.
    """
    edits = [(probe["path"], probe["anchor"], probe["weakening"])] + [
        (also["path"], also["anchor"], also["weakening"]) for also in probe.get("also", [])
    ]
    originals: dict[str, str] = {}
    weakened: dict[str, str] = {}
    for path, anchor, weakening in edits:
        target = tree / path
        if not target.is_file():
            raise ManifestError(f"{where}: STALE — {path} does not exist")
        if path not in originals:
            originals[path] = target.read_text()
            weakened[path] = originals[path]
        # AGAINST THE TEXT AS ALREADY WEAKENED, not against the original: two sites of one
        # carrying set routinely live in ONE file, and applying each to a fresh copy of the
        # original would keep only the last -- a compound probe that silently weakened one
        # site while reporting that it had removed the set.
        hits = weakened[path].count(anchor)
        if hits != 1:
            raise ManifestError(
                f"{where}: STALE — an anchor matches {hits} site(s) in {path}, "
                f"expected exactly 1. Re-adjudicate this probe against the current "
                f"implementation; do NOT restore the old code to make it match."
            )
        weakened[path] = weakened[path].replace(anchor, weakening, 1)
    return {path: (originals[path], weakened[path]) for path in originals}


def declared_members(unit: dict) -> set[str]:
    """The names a probe may expect red: the unit's `tested_symbols`, and its gates."""
    return {str(s) for s in unit.get("tested_symbols", [])} | {
        f"gate#{g}" for g in unit.get("gate_controls", [])
    }


def undeclared_expectations(unit: dict, probe: dict) -> list[str]:
    """The `expect_red` names the unit does not declare. A control outside the battery is
    not evidence, however red it goes."""
    declared = declared_members(unit)
    return [name for name in probe["expect_red"] if name not in declared]
