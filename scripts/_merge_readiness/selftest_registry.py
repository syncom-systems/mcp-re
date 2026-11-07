# SPDX-License-Identifier: Apache-2.0
"""Selftest: which units a change affects, and that the registry comes from the commit."""

from __future__ import annotations

from _merge_readiness.candidate import VERIFICATION_TOML, git, manifest_at
from _merge_readiness.errors import Undecidable
from _merge_readiness.tally import Tally

import _affected  # noqa: E402
from _boundary_crossings import expand_paths  # noqa: E402
from _manifest import load_verification  # noqa: E402


def _build_inputs_widen(tally: Tally, manifest: dict) -> None:
    """A build-input change must widen to every unit, not to the units that declare it."""
    every = _affected.by_paths(manifest["unit"], manifest.get("edge", []), {"bazel/crates.lock"})
    tally.expect(
        len(every) == len(manifest["unit"]),
        f"a crates.lock change widened to {len(every)} of {len(manifest['unit'])} units",
    )


def _synthetic_globs(tally: Tally) -> None:
    """A glob entry in a unit's `paths` names the files it expands to. A prefix test can never
    match one, so a change confined to a globbed directory went uncounted (#1242)."""
    synthetic = [{"id": "g", "paths": ["src/serve/**/*.rs"]}]
    for path, want in (("src/serve/a.rs", True), ("src/serve/x/y/a.rs", True),
                       ("src/serve/a.py", False), ("src/other/a.rs", False)):
        if ("g" in _affected.by_paths(synthetic, [], {path})) != want:
            tally.fail(f"glob unit path vs {path}: wanted affected={want}")


def _only_the_glob_names(unit: dict, pattern: str) -> list[str]:
    """The files `pattern` expands to that no literal path of `unit` already declares."""
    literal = [p for p in unit.get("paths", []) if not _affected.is_glob(p)]
    return sorted(f for f in expand_paths([pattern])
                  if not any(_affected.declares(p, f) for p in literal))


def _declared_globs(tally: Tally, manifest: dict) -> None:
    """The same, over the registry as declared: every glob entry reaches its unit through a
    file only the glob names. Counted, so an empty population cannot read as a pass."""
    globbed = 0
    for unit in manifest["unit"]:
        for pattern in (p for p in unit.get("paths", []) if _affected.is_glob(p)):
            only = _only_the_glob_names(unit, pattern)
            if not only:
                continue
            globbed += 1
            if unit["id"] not in _affected.by_paths([unit], [], {only[0]}):
                tally.fail(f"{unit['id']}: a change to {only[0]} (named by {pattern}) is not counted")
    tally.expect(
        globbed > 0,
        "no unit declares a glob path that names a file of its own; the control measured nothing",
    )


def _registry_from_the_commit(tally: Tally) -> None:
    """The registry the required set is derived from must come from the COMMIT, not the
    tree. Perturbed rather than asserted: a version of `manifest_at` that read the tree
    would return the tree's unit count for every sha, so the control compares two
    commits that declare DIFFERENT numbers and requires the answers to differ with them.
    `git log -1 --format=%H -- <path>` finds the last commit that CHANGED the registry,
    so its parent is guaranteed to carry a different one wherever history has any."""
    changed_at = git("log", "-1", "--format=%H", "--", VERIFICATION_TOML)
    if not changed_at:
        return
    parent = git("rev-parse", f"{changed_at}^")
    for sha, read in ((changed_at, len(manifest_at(changed_at).get("unit", []))),
                      (parent, len(manifest_at(parent).get("unit", [])))):
        declared = git("show", f"{sha}:{VERIFICATION_TOML}").count("\n[[unit]]")
        if read != declared:
            tally.fail(f"manifest_at({sha[:12]}) read {read}; the blob declares {declared}")


def _no_registry_is_undecidable(tally: Tally) -> None:
    """A candidate carrying no registry, or naming no commit, is UNDECIDABLE — never a
    verdict. `git()` raises it; this asserts the gate does not swallow it somewhere."""
    try:
        manifest_at("0000000000000000000000000000000000000000")
    except Undecidable:
        return
    tally.fail("a candidate with no readable registry produced a manifest anyway")


def run(tally: Tally) -> None:
    manifest = load_verification()
    _build_inputs_widen(tally, manifest)
    _synthetic_globs(tally)
    _declared_globs(tally, manifest)
    _registry_from_the_commit(tally)
    _no_registry_is_undecidable(tally)
