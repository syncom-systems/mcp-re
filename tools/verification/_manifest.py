# SPDX-License-Identifier: Apache-2.0
"""Loading and validation of `verification.toml`: the ADR-MCPRE-059 units and typed edges.

Strict by construction: an unknown key is a validation FAILURE, not a field that is
silently ignored (ADR-MCPRE-059, "Authoritative manifest"). A typo in a security
declaration must not read as an absent declaration.

The other registries load beside this one: `_assumptions`, `_trust_boundaries` and
`_toolchain_lock`. The record-level primitives they share are `_record_rules`.

Stdlib only. This is analysis tooling, not production code, and it must run before any
verification toolchain exists.
"""

from __future__ import annotations

import functools
import os
import sys

from _ecosystems import RUST
from _ecosystems import Ecosystem
from _ecosystems import valid_target
import _module_tree
import _record_rules
import _rust_targets
from _ecosystems import unit_ecosystem
from _ecosystems import unit_projects
from _evidence_class import MEASUREMENT_KEYS
from _lanes import claims
import _registries
import _toolchains
from _registries import REPO_ROOT
from _edges import validate_edges
from _record_rules import reject_unknown, require
from _unit_rules import validate_proof_selection, validate_unit_identity
from _registries import ManifestError

VERIFICATION_TOML = _registries.path("verification")
TOOLCHAINS_LOCK_TOML = _toolchains.path()

#: Bumped to 2 by ADR-MCPRE-068 Phase 0A, which made `evidence_class` and
#: `direct_consequence_severity` required on every unit. The bump is not bookkeeping: the
#: refusal below says a schema change alters what a fingerprint MEANS, so every standing
#: attestation is invalidated by it and must be re-earned against the new fingerprints.
SCHEMA_VERSION = 2

#: Freshness states, ADR-MCPRE-059 §5.
STATES = {
    "FRESH",
    "DIRTY_SELF",
    "DIRTY_CONTRACT",
    "DIRTY_DEPENDENCY",
    "DIRTY_ASSUMPTION",
    "DIRTY_POLICY",
    "DIRTY_TOOLCHAIN",
    "DIRTY_EVIDENCE",
    "UNKNOWN",
    "BLOCKED",
}

_VERIFICATION_TOP = {
    "schema_version",
    "policy_revision",
    "unknown_is_dirty",
    "formal_model_revision",
    "threat_model_revision",
    "unit",
    "edge",
}
_UNIT_KEYS = {
    "id",
    "class",
    "description",
    "paths",
    "exported_contracts",
    # `consumed_contracts` was here. It is DERIVED from the incoming CONTRACT_CONSUMES
    # edges now — see `_MOVED_AUTHORITY`.
    "evidence",
    "features",
    "pilot",
    "proved_symbols",
    "tested_symbols",
    "extracted_symbols",
    "lean_theorems",
    # ADR-MCPRE-068 §5. `evidence_class` cannot be called `class`: that key is two lines up
    # and holds V0/V1/V2. The two vocabularies are unrelated — one is proof STRENGTH, the
    # other is the KIND of thing that establishes the claim — and a V0 unit can be any of
    # the four evidence classes.
    "evidence_class",
    "direct_consequence_severity",
    # ADR-MCPRE-068 Phase 1. A control that is a SCRIPT rather than a test symbol: a gate
    # that reads production source and refuses a violating pattern. It is declared here and
    # not in `tested_symbols` because the two are resolved by different runners — a Bazel test
    # or pytest selector names a symbol inside a compiled battery, and this names an executable
    # the lane invokes over the tree. Flattening them would make every symbol resolver have
    # to recognise a path that is not a symbol.
    "gate_controls",
    *MEASUREMENT_KEYS,
}

def _unit_packages(unit: dict) -> list[str]:
    """The projects the unit's declared paths live in, sorted.

    Shared by the schema check and by `verify-tests`, because "which projects does this unit
    name" must not have two answers. Which BUILD SYSTEM answers it is `_ecosystems`'
    (issue #745).
    """
    return unit_projects(unit)


@functools.lru_cache(maxsize=None)
def _crate_modules(crate_root: str) -> dict[tuple[str, ...], str]:
    """Module path -> repository path, for every file `crate_root` reaches."""
    tree = _module_tree.walk(_rust_targets.REPO_ROOT / crate_root)
    base = _rust_targets.REPO_ROOT.resolve()
    return {f.module: os.path.relpath(f.path.resolve(), base) for f in tree.files}


def _module_candidates(crate_root: str, symbol_path: str) -> list[str]:
    """The source files an IN-CRATE selector's module path names, longest prefix first.

    A selector on a test target built from a crate executes code in that crate's module
    tree: `rejection::tests::x` on the proxy's unit tests can only execute code in
    `mcp-re-proxy/src/rejection.rs`. Every prefix that is a FILE of the tree is offered,
    because the selector names an item, not a file, and the file boundary can be anywhere
    above it. Which file a module is — `#[path]`, both file forms, inline modules — is
    `_module_tree`'s answer.
    """
    segments = tuple(s for s in symbol_path.split("::") if s)
    modules = _crate_modules(crate_root)
    return [modules[segments[:d]] for d in range(len(segments), 0, -1) if segments[:d] in modules]


def _validate_gate_controls(uwhere: str, unit: dict) -> None:
    """Every declared gate control exists in the tree and can be started.

    A gate control is a CONTROL: a probe's `expect_red` may name it, and the lane runs it to
    see whether a weakening turns it red. So it must exist and be runnable, or the lane
    would report a measurement failure as a finding about the code.

    The claim's closure must ALSO cover it, and that is not bookkeeping. A gate's rules are
    the production carrier of the proposition — weakening a rule weakens the claim exactly
    as deleting a runtime check does. A control outside the closure could be softened under
    a standing PASS, which is the ADR-MCPRE-069 defect these two gates were found in.

    That coverage is NOT `paths` membership, and trying it first is how the reason got
    written down: a `.py` entry in a Rust unit's paths collapses `unit_ecosystem` to None,
    and the test lane then reports every `tested_symbols` member as naming no runnable
    target. The unit's source closure is single-ecosystem by construction. So the scripts
    are digested as their own fingerprint component (`_fingerprint._unit_components`), and
    what this function owes is the part a digest cannot state: that the control EXISTS and
    can START.

    "Can start" is READABLE, not executable, and the difference is measured rather than
    assumed: both registered gates are invoked as `python3 <path>` — by `ci.yml`, by
    `local_gate.sh` and by this lane — so the execute bit decides nothing about whether they
    run. `authorization_provenance_gate.py` is mode 100644 today and runs in CI on every
    push. Demanding the bit here would be a requirement no invoker has, failing a control
    that starts perfectly well; the execute bit is `merge_path_gate.py`'s question, about
    scripts that ARE invoked by path.
    """
    declared = [str(entry) for entry in unit.get("gate_controls", [])]
    if not declared:
        return
    for control in declared:
        script = REPO_ROOT / control
        if not script.is_file():
            raise ManifestError(
                f"{uwhere}: gate_control {control!r} is not a file in the tree. A control "
                f"the lane cannot run is not evidence, however it is described."
            )
        if not os.access(script, os.R_OK):
            raise ManifestError(
                f"{uwhere}: gate_control {control!r} cannot be read, so the lane cannot "
                f"start it and would report its own inability as a verdict about the code."
            )


def _validate_in_crate_selectors(uwhere: str, unit: dict) -> None:
    """A selector on a test target BUILT FROM A CRATE must execute code the unit's `paths` measure.

    Integration-test sources enter the fingerprint as their own component; the unit tests
    of a crate do not, because they live inside the source files the unit already declares.
    That is only true if it IS true, so it is checked rather than assumed: a selector whose
    module is not in `paths` would be a battery member whose body could be rewritten with
    no fingerprint moving — the same false-freshness shape as an unmeasured implementation.

    A binary crate's tests are built from the binary the same way, and carry the identical
    obligation. Exempting them would let a deployable's own controls sit outside every
    fingerprint component.
    """
    if unit_ecosystem(unit) is not RUST:
        return
    declared = set(unit["paths"])
    for symbol in unit.get("tested_symbols", []):
        label, _, path = str(symbol).partition("#")
        row = _rust_targets.target(label)
        if row is None or not row["crate"]:
            continue
        root_dir = row["root"].rsplit("/", 1)[0]
        # The crate root itself holds the modules it declares inline, `tests` among them.
        candidates = _module_candidates(row["root"], path) + [row["root"]]
        if not any(c in declared for c in candidates):
            raise ManifestError(
                f"{uwhere}: tested_symbol {symbol!r} executes code in {root_dir}, but no "
                f"prefix of its module path is among this unit's `paths`. An in-crate test "
                f"whose source the unit does not measure can be rewritten under the same "
                f"name without moving the fingerprint. Declare the module's file."
            )


def _validate_rust_test_packages(uwhere: str, unit: dict) -> None:
    """Every Rust selector's test target lives in a package this unit's paths name.

    The battery must run inside the measured source closure: a selector naming a target in
    a package the unit does not declare would measure code whose source no component of the
    fingerprint digests. The label states its package, so the check is on the label itself.
    """
    if unit_ecosystem(unit) is not RUST:
        return
    packages = set(_unit_packages(unit))
    for symbol in unit.get("tested_symbols", []):
        label = str(symbol).partition("#")[0]
        row = _rust_targets.target(label)
        if row is not None and row["package"] not in packages:
            raise ManifestError(
                f"{uwhere}: tested_symbol {symbol!r} runs in package {row['package']!r}, "
                f"which none of this unit's paths name ({', '.join(sorted(packages))}). The "
                f"battery must run inside the measured source closure."
            )


def _validate_header(where: str, doc: dict) -> None:
    """The document-level refusals: keys, schema version, and the fail-closed policy."""
    reject_unknown(where, doc, _VERIFICATION_TOP)
    require(
        where,
        doc,
        {"schema_version", "policy_revision", "unknown_is_dirty"},
    )
    if doc["schema_version"] != SCHEMA_VERSION:
        raise ManifestError(
            f"{where}: schema_version {doc['schema_version']} but this tooling "
            f"implements {SCHEMA_VERSION}. A schema change alters what a fingerprint "
            f"means, so it invalidates every attestation and must be handled, not "
            f"tolerated."
        )
    if doc["unknown_is_dirty"] is not True:
        raise ManifestError(
            f"{where}: unknown_is_dirty must be true. Turning it off is a policy change "
            f"that removes the fail-closed property the whole graph rests on; it cannot "
            f"be done by editing this field alone."
        )


def _is_runnable(eco: Ecosystem | None, target: str, path: str) -> bool:
    """The selector has a path, and `eco` is a single ecosystem that runs `target`."""
    if not path or eco is None:
        return False
    return valid_target(eco, target)


def _require_runnable_target(uwhere: str, symbol: object, eco: Ecosystem | None) -> None:
    """A `tested_symbol` names a target its unit's ecosystem can run, and a path inside it."""
    target, _, path = str(symbol).partition("#")
    # The target is required, not defaulted: a defaulted target lets a test
    # that moved between the lib and an integration target keep reporting under
    # the one it left.
    # WHICH targets exist is the ecosystem's answer (issue #745): a Rust
    # selector names a Bazel test target in the build graph, while a pytest or
    # vitest battery has the one target that says which runner reads the
    # selector. A unit whose paths name no single ecosystem has no runnable
    # target at all, which is the same refusal for a different reason.
    if not _is_runnable(eco, target, path):
        raise ManifestError(
            f"{uwhere}: tested_symbol {symbol!r} names no runnable "
            f"{eco.name if eco else '<unresolved ecosystem>'} target; "
            f"rust takes `//pkg:test_target#path::to::test`, a Bazel "
            f"`rust_test` or `rust_doc_test`; python takes "
            f"`pytest#tests/file.py::name`; typescript takes "
            f"`vitest#test/file.test.ts > suite > name`"
        )


def _validate_test_battery(uwhere: str, unit: dict) -> None:
    """`test://` evidence and `tested_symbols` agree, and every member is runnable."""
    # The same argument one class down. A `test://` URI names a battery, and a battery
    # with no declared members is a description: the lane would have nothing to select,
    # and "the tests passed" would mean "no test was asked for".
    if claims(unit, "test"):
        if not unit.get("tested_symbols"):
            raise ManifestError(
                f"{uwhere}: declares test:// evidence but no `tested_symbols`. A "
                f"battery with no named members cannot be run, and an unrunnable "
                f"claim is not evidence."
            )
        eco = unit_ecosystem(unit)
        for symbol in unit["tested_symbols"]:
            _require_runnable_target(uwhere, symbol, eco)
    elif unit.get("tested_symbols"):
        # Declared members with no `test://` URI claiming them would run a battery
        # whose result no evidence entry reads — measurement nothing consumes.
        raise ManifestError(
            f"{uwhere}: declares `tested_symbols` but no test:// evidence entry "
            f"claims them, so nothing consumes what the lane would measure."
        )


def _validate_unit(uwhere: str, unit: dict, seen_ids: set[str], tree_checks: bool) -> None:
    """Every admission rule one `[[unit]]` record owes, in the order they are checked."""
    reject_unknown(uwhere, unit, _UNIT_KEYS)
    require(uwhere, unit, {"id", "class", "paths"})
    validate_unit_identity(uwhere, unit, seen_ids, tree_checks)
    validate_proof_selection(uwhere, unit)
    _validate_test_battery(uwhere, unit)
    if tree_checks:
        _validate_gate_controls(uwhere, unit)
        _validate_rust_test_packages(uwhere, unit)
        _validate_in_crate_selectors(uwhere, unit)
    # `mutation://` is a claim about a NEGATIVE battery, which only exists on top of a
    # positive one: the probes' `expect_red` names members of `tested_symbols`. A unit
    # claiming mutation evidence without test evidence would declare controls that are
    # not evidence for anything.
    if claims(unit, "mutation") and not claims(unit, "test"):
        raise ManifestError(
            f"{uwhere}: declares mutation:// evidence without test:// evidence. A "
            f"mutation probe asserts that a DECLARED control goes red; with no "
            f"declared battery there is nothing for it to name."
        )


def load_verification(*, tree_checks: bool = True) -> dict:
    """Load and validate `verification/policy/verification.toml`.

    `tree_checks=False` validates the DOCUMENT only: what each declared path, gate control
    and in-crate selector resolves to is a question about a checkout, and a caller measuring
    a commit it does not check out has no checkout that commit describes.
    """
    doc = _record_rules.load_registry(VERIFICATION_TOML)
    where = "verification.toml"
    _validate_header(where, doc)

    seen_ids: set[str] = set()
    #: What each unit exports, BY unit id. A flat set would answer "somebody exports this",
    #: and the question a contract edge asks is "does THIS producer export it".
    exports: dict[str, set[str]] = {}
    for index, unit in enumerate(doc.get("unit", [])):
        _validate_unit(f"{where} [[unit]] #{index}", unit, seen_ids, tree_checks)
        exports[unit["id"]] = set(unit.get("exported_contracts", []))

    validate_edges(where, doc.get("edge", []), seen_ids, exports)
    return doc


def fail(message: str) -> None:
    """Print a fatal manifest/lane error and exit non-zero."""
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)
