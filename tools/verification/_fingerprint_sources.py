# SPDX-License-Identifier: Apache-2.0
"""The source, build and toolchain components of a unit fingerprint.

What the unit's code IS: the files it declares, the whole project a prover run reads, the
generated model it is measured against, the dependency and configuration inputs that decide
what its source means, and the pinned toolchains that build and check it.
"""

from __future__ import annotations

from _ecosystems import RUST
from _ecosystems import build_configuration_patterns
from _ecosystems import formal_source_patterns
from _ecosystems import unit_projects
from _fingerprint_digest import digest_paths
from _fingerprint_digest import digest_tracked
from _lanes import claims
from _lean_sources import generated_model_paths

#: Where extraction deposits machine-generated proof input. Units do not declare paths here
#: — see `generated_inputs`, which derives the population from the lakefile instead.
GENERATED_ROOT = "verification/lean/generated"


def unit_crates(unit: dict) -> list[str]:
    """The projects the unit's declared paths live in.

    Derived from the paths rather than configured, for the reason `verify-verus` derives
    its `-p` argument the same way: a unit whose source moves to another project must not
    keep fingerprinting the one it left. Which build system decides what a project IS is
    `_ecosystems`' (issue #745).
    """
    return unit_projects(unit)


def crate_sources(crates: list[str]) -> dict[str, str]:
    return digest_paths([f"{crate}/src/**/*.rs" for crate in crates])


def formal_sources(unit: dict) -> dict[str, str]:
    """Whole-project sources for a unit whose evidence comes from a prover run.

    Empty where the ecosystem has no prover lane, which is what keeps a V1/V3 declaration
    over Python or TypeScript source from deriving a fingerprint that pretends a whole-
    project measurement happened. The class check that refuses such a unit outright is the
    schema's; this is the half that would otherwise measure it as if it had one.
    """
    return digest_tracked(formal_source_patterns(unit))


def generated_inputs(unit: dict) -> dict[str, str]:
    """The machine-generated proof input this unit's evidence was measured against.

    Declared paths under `GENERATED_ROOT`, UNION the extracted modules the Lean package
    actually elaborates. The paths half alone was a component with an empty population: no
    unit lists a file under `verification/lean/generated/`, and none should — a `.lean` path
    in a Rust unit's `paths` collapses `unit_ecosystem` to None and takes the test lane's
    target resolution with it. So the declared invalidation rule `generated-model drift ->
    DIRTY_EVIDENCE` was wired to nothing, and measured 0 of 244 units.

    Derived from the unit's extraction DECLARATION instead: a unit claiming `lean://` is
    measured against the model the lakefile's libraries resolve to, which is what
    `regenerate-lean` produces and what `lake build` elaborates.
    """
    declared = [p for p in unit["paths"] if p.startswith(GENERATED_ROOT)]
    if not claims(unit, "lean"):
        return digest_paths(declared)
    return digest_paths(sorted({*declared, *generated_model_paths()}))


def build_configuration(unit: dict, formal_closure: list[str]) -> dict[str, str]:
    """The dependency and configuration inputs that decide what this unit's source IS.

    Ecosystem-supplied (`build_configuration_patterns`), because a Python project's
    `pyproject.toml` and `uv.lock` bear exactly the weight a crate's `BUILD.bazel` and the
    module lock bear: a dependency swap or a lockfile bump alters what a claim is
    about without touching a declared source line. Absent alternatives — `poetry.lock` where
    a project uses `uv` — contribute nothing rather than an error.

    `formal_closure` closes R9-C039/R9-C040. A formal unit's `proof_dependencies` digests
    the SOURCE of the crates the prover compiles alongside it, and nothing digested their
    manifests — so the `verify` feature could stop travelling down the closure, or a
    dependency of a dependency could be swapped, and the unit still derived FRESH over a
    prover run that had checked something else. The source of a crate and the manifest that
    decides what that crate IS are the same input to this question, and it was answered for
    the unit's own crates and not for the ones its proof reaches through.
    """
    patterns = build_configuration_patterns(unit)
    for project in formal_closure:
        patterns.extend(f"{project}/{name}" for name in RUST.project_inputs)
    return digest_tracked(patterns)


def _scalars(entry: dict) -> dict:
    return {
        key: value
        for key, value in sorted(entry.items())
        if not isinstance(value, dict) and key != "note"
    }


def _subtables(name: str, entry: dict) -> dict[str, dict]:
    return {
        f"{name}.{sub_name}": {key: value for key, value in sorted(sub.items()) if key != "note"}
        for sub_name, sub in sorted(entry.items())
        if isinstance(sub, dict)
    }


def _governs(entry: dict, ecosystem: str | None) -> bool:
    scope = entry.get("ecosystem")
    return scope is None or scope == ecosystem


def toolchain_identity(toolchains: dict, ecosystem: str | None = None) -> dict:
    """Every pinned identity governing this unit, plus every unresolved one named as such.

    ECOSYSTEM-SCOPED ENTRIES are the exception, and they exist because a runtime is a
    toolchain that governs one family of units. A table declaring `ecosystem = "python"`
    enters the fingerprint of Python units only: the interpreter decides the outcome of the
    Python batteries and of nothing else, so making a CPython patch bump dirty all 76 units
    — every Rust one included — would state a blast radius that did not happen, and a blast
    radius nobody believes is one people learn to re-baseline past.

    An entry with no `ecosystem` key governs everything, which is what every pin above the
    runtime does: the Rust channel, the provers, the extraction container, the schema.
    """
    identity: dict[str, object] = {}
    for name, entry in sorted(toolchains.items()):
        if name == "schema_version" or not isinstance(entry, dict):
            continue
        if not _governs(entry, ecosystem):
            continue
        identity[name] = _scalars(entry)
        identity.update(_subtables(name, entry))
    return identity
