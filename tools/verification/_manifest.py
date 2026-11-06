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
from _evidence_class import class_problems
from _evidence_class import severity_problem
import _registries
import _toolchains
from _registries import REPO_ROOT
import _tree
from _record_rules import reject_unknown, require
from _registries import ManifestError

VERIFICATION_TOML = _registries.path("verification")
TOOLCHAINS_LOCK_TOML = _toolchains.path()

#: Bumped to 2 by ADR-MCPRE-068 Phase 0A, which made `evidence_class` and
#: `direct_consequence_severity` required on every unit. The bump is not bookkeeping: the
#: refusal below says a schema change alters what a fingerprint MEANS, so every standing
#: attestation is invalidated by it and must be re-earned against the new fingerprints.
SCHEMA_VERSION = 2

#: Verification classes, ADR-MCPRE-059 §9.
CLASSES = {"V0", "V1", "V2", "V3"}

#: The classes as an ordered scale, so "past the class this boundary permits" is a
#: comparison rather than a reading of the manifest by a human.
CLASS_ORDER = {"V0": 0, "V1": 1, "V2": 2, "V3": 3}

#: Typed edge kinds, ADR-MCPRE-059 §4. Collapsing these into one "depends on" relation is
#: forbidden once invalidation is enforced, so the set is closed here.
EDGE_KINDS = {
    "COMPILE_DEPENDENCY",
    "CONTRACT_CONSUMES",
    "PROOF_DEPENDENCY",
    "TEST_EVIDENCE",
    "TRUSTS_ASSUMPTION",
    "GENERATED_FROM",
    "REVIEW_CONTEXT",
}

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
_EDGE_KEYS = {"kind", "from", "to", "contract", "sealed", "sealed_by", "rationale"}

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


def validate_edges(
    where: str, edges: list[dict], unit_ids: set[str], exports: dict[str, set[str]]
) -> None:
    """The admission rules for typed edges — ADR-MCPRE-059 §4.

    Separate from `load_verification` because the rules below are a proposition about what
    an edge kind MEANS, and a proposition whose only exercise is that the committed manifest
    happens to satisfy it has never been shown to refuse anything.

    The contract rule, and why it is stated for every contract edge rather than only for a
    sealed one: `CONTRACT_CONSUMES` asserts a relation to the producer's PUBLISHED INTERFACE,
    which is a stronger claim than "this consumer compiles against that producer". Nine edges
    carried the kind while naming no contract, and none of their producers exported one — so
    the graph said "contract relation" about nine compile-time dependencies, and
    `consumed_contracts` had no relation to derive itself from. An edge that cannot name a
    contract its own producer exports is a `COMPILE_DEPENDENCY`; the fix is never to invent
    the contract.

    `sealed` is an ADDITIONAL property of an already-valid contract relation — the claim that
    the contract is the WHOLE of the consumer's reasoning — not what makes the relation a
    contract relation. So an unsealed contract edge is legitimate, and the contract is
    required either way.
    """
    for index, edge in enumerate(edges):
        ewhere = f"{where} [[edge]] #{index}"
        _validate_edge_shape(ewhere, edge, unit_ids)
        if edge["kind"] == "CONTRACT_CONSUMES":
            _validate_contract_relation(ewhere, edge, exports)
        if edge.get("sealed"):
            _validate_seal(ewhere, edge)


def _validate_edge_shape(ewhere: str, edge: dict, unit_ids: set[str]) -> None:
    """An edge has known keys, a closed kind, and endpoints that are declared units."""
    reject_unknown(ewhere, edge, _EDGE_KEYS)
    require(ewhere, edge, {"kind", "from", "to"})
    if edge["kind"] not in EDGE_KINDS:
        raise ManifestError(
            f"{ewhere}: kind {edge['kind']!r} not one of {sorted(EDGE_KINDS)}"
        )
    for endpoint in ("from", "to"):
        if edge[endpoint] not in unit_ids:
            raise ManifestError(
                f"{ewhere}: {endpoint} {edge[endpoint]!r} is not a declared unit"
            )


def _validate_contract_relation(
    ewhere: str, edge: dict, exports: dict[str, set[str]]
) -> None:
    """A `CONTRACT_CONSUMES` edge names a contract its own producer exports."""
    require(ewhere, edge, {"contract"})
    # Exported by THIS edge's `from`, not by some unit somewhere. The previous check
    # ran only under `sealed` and compared against the union of every unit's exports,
    # so a seal could name a contract an unrelated unit published — a relation
    # between two units justified by a third.
    if edge["contract"] not in exports.get(edge["from"], set()):
        raise ManifestError(
            f"{ewhere}: CONTRACT_CONSUMES names contract {edge['contract']!r}, "
            f"which {edge['from']!r} does not export. A contract edge is a relation "
            f"to the PRODUCER's published interface; if this dependency is real but "
            f"no such contract exists, it is a COMPILE_DEPENDENCY."
        )


def _validate_seal(ewhere: str, edge: dict) -> None:
    """Only a contract edge may be sealed, and a seal says who sealed it and why."""
    if edge["kind"] != "CONTRACT_CONSUMES":
        raise ManifestError(
            f"{ewhere}: only a CONTRACT_CONSUMES edge may be sealed. Sealing "
            f"means source-only dirtiness stops at a proved unchanged contract, "
            f"which is meaningless without a contract."
        )
    require(ewhere, edge, {"sealed_by", "rationale"})


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


def _validate_unit_identity(
    uwhere: str, unit: dict, seen_ids: set[str], tree_checks: bool
) -> None:
    """The record's own identity: declared class, unique id, and paths that resolve.

    Records `unit["id"]` in `seen_ids`, which is how a duplicate is caught across units.
    """
    _refuse_unadmitted_class(uwhere, unit)
    if unit["id"] in seen_ids:
        raise ManifestError(f"{uwhere}: duplicate unit id {unit['id']!r}")
    seen_ids.add(unit["id"])
    if tree_checks:
        _require_paths_resolve(uwhere, unit)


def _refuse_unadmitted_class(uwhere: str, unit: dict) -> None:
    """The declared class is a known one that the record's own evidence satisfies."""
    # ADR-MCPRE-068 §9.3, registry adequacy: declaring a class you do not satisfy is a
    # lie and is fatal here, at load, before anything reads the unit. Every rule
    # `class_problems` applies is computable from THIS record alone, which is what
    # keeps it loader-stage; N1's falsifier obligation needs `effective_severity` from
    # the assurance graph and activates in Phase 0E instead.
    for problem in class_problems(uwhere, unit):
        raise ManifestError(problem)
    problem = severity_problem(uwhere, unit)
    if problem is not None:
        raise ManifestError(problem)
    if unit["class"] not in CLASSES:
        raise ManifestError(
            f"{uwhere}: class {unit['class']!r} not one of {sorted(CLASSES)}"
        )


def _require_paths_resolve(uwhere: str, unit: dict) -> None:
    """Every declared path names at least one file in the current tree."""
    for declared in unit["paths"]:
        if not _tree.current().files(declared):
            raise ManifestError(
                f"{uwhere}: path {declared!r} matches nothing. A unit whose source "
                f"cannot be located has unknown provenance, which is dirty, not empty."
            )


def _require_extraction_selection(uwhere: str, unit: dict) -> None:
    """A V2/V3 unit names what the extracted-model lane measures, and says so in `evidence`.

    The extracted-model lane's two halves of the same argument, and they are separate
    keys because they name different things in different languages: which RUST items
    Charon starts from, and which LEAN theorems the prover is asked about. Deriving
    either from the other would be a guess about a name mangling that Aeneas owns.

    Kept apart from `proved_symbols` deliberately. That key is the Verus lane's, and a
    V3 unit claims BOTH lanes — one key read by two provers with two naming schemes is
    a key that means whichever the reader assumed.
    """
    for key, what in (
        ("extracted_symbols", "the Rust items the model is extracted from"),
        ("lean_theorems", "the Lean theorems the prover is asked about"),
    ):
        if not unit.get(key):
            raise ManifestError(
                f"{uwhere}: class {unit['class']} requires `{key}` — {what}. A "
                f"unit claiming extracted-model evidence with an empty selection "
                f"asks the lane to measure nothing, and nothing measured passes."
            )
    # AND IT MUST SAY SO IN ITS EVIDENCE. Two authorities read "what does this unit
    # require": `_evidence.required_lanes` derives it from the declared URIs, and the
    # aggregate's requirement set derives it from the class. They agree only while
    # every V2/V3 unit declares `lean://` — and nothing made it. A unit with the
    # selection keys above and no `lean://` entry would be ISSUED an attestation on
    # its test battery alone while claiming extracted-model evidence, because the
    # issuer would see no lean lane to check.
    if not claims(unit, "lean"):
        raise ManifestError(
            f"{uwhere}: class {unit['class']} declares an extraction selection but "
            f"no `lean://` evidence entry. The class says the Lean lane must "
            f"measure this unit and the evidence list is where a unit says which "
            f"lanes are asked about it, so the two must agree — otherwise the "
            f"issuer checks a lane the class requires and the manifest never named."
        )


def _validate_proof_selection(uwhere: str, unit: dict) -> None:
    """What each proof class must name, and that no class names what no lane reads."""
    # A V1/V3 unit must name the symbols its proof is about. Without that the lane can
    # only ask "did this crate verify something", and deleting one of two
    # specifications leaves the other to answer yes — coverage silently halves while
    # the gate stays green. Naming them turns a deleted theorem into a lane failure.
    if unit["class"] in {"V1", "V3"} and not unit.get("proved_symbols"):
        raise ManifestError(
            f"{uwhere}: class {unit['class']} requires `proved_symbols`. A unit that "
            f"claims formal evidence must name the symbols proved, or nothing "
            f"distinguishes a deleted specification from a passing one."
        )
    if unit["class"] in {"V2", "V3"}:
        _require_extraction_selection(uwhere, unit)
    elif unit.get("extracted_symbols") or unit.get("lean_theorems"):
        raise ManifestError(
            f"{uwhere}: declares extraction selection but is class {unit['class']}, so "
            f"no lane reads it. A selection nothing consumes is a declaration that "
            f"reads as coverage and measures nothing."
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
    _validate_unit_identity(uwhere, unit, seen_ids, tree_checks)
    _validate_proof_selection(uwhere, unit)
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
