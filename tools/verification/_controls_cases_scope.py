# SPDX-License-Identifier: Apache-2.0
"""Positive scope: a NAMED control per supported ecosystem must be discovered, and the
gate, doctest and attribute shapes the census recognises."""

from __future__ import annotations

import tempfile
from pathlib import Path

import _controls
import _gates
import _rust_targets
from _control_rust import TEST_ATTR
from _controls_cases_support import CONTROLS, INDEX, REPORT

#: Each entry is `(project, identity)` of a control that exists on main and a note saying
#: what its absence would mean. Named rather than counted: a count survives the loss of a
#: whole discovery path as long as some other path grew.
SCOPE: dict[str, tuple[str, str]] = {
    "rust-test (library crate root)": (
        "mcp-re-proxy",
        "src/lib.rs#runtime_state::tests::the_relation_has_exactly_ten_legal_transitions",
    ),
    "rust-test (integration crate root)": (
        "mcp-re-proxy",
        "tests/integration/main.rs#client_verifier_posture_test::"
        "the_builder_enforces_expiration_and_admits_no_posture_argument",
    ),
    "rust-test (binary crate root)": (
        "mcp-re-client",
        "src/main.rs#startup::tests::"
        "the_serving_path_starts_the_anchor_refresher_and_anchors_are_withdrawn_on_expiry",
    ),
    "rust-doctest (compile_fail)": (
        "mcp-re-client-core",
        "doc#delegated_trust::DelegatedResponseTrust",
    ),
    "pytest (sdk project)": (
        "sdk/python",
        "pytest#tests/test_nonce_floor.py::test_a_sub_floor_override_is_refused_at_sign_time",
    ),
    "pytest (repository tooling)": (
        ".",
        "pytest#tools/verification/test_controls.py::"
        "test_every_supported_ecosystem_has_a_discovered_control",
    ),
    "vitest": (
        "sdk/typescript",
        "vitest#test/nonce_floor.test.ts > sign-time nonce floor > "
        "a sub-floor override is refused at sign time: %s",
    ),
    "structural probe": ("", "structural#S01"),
    "mutation probe": ("", "mutation#M01-request-signature"),
    "gate": ("", "gate#scripts/module_size_gate.py"),
}


#: A gate a unit CLAIMS, through `gate_controls` rather than through `tested_symbols`.
#: ADR-MCPRE-068 Phase 1 registered four of these as the production carriers of theorems a
#: type could not establish; a census reading only `tested_symbols` would report all four as
#: unclaimed and invite a `not-evidence` reason about the carrier of a `critical` claim.
CLAIMED_GATE = ("", "gate#scripts/serving_identity_provenance_gate.py")


def every_supported_ecosystem_has_a_discovered_control():
    """Each named control is found, so no discovery path has gone dark."""
    missing = [name for name, key in SCOPE.items() if key not in INDEX]
    assert not missing, f"the census cannot see: {missing}"


def test_a_gate_a_unit_declares_is_claimed():
    """`gate_controls` is a claim, and the census must read it as one."""
    assert CLAIMED_GATE in INDEX, "the claimed gate moved; retarget this control"
    assert CLAIMED_GATE in REPORT.claimed
    claimed_gates = {
        (c.control.project, c.control.identity)
        for c in REPORT.claims
        if c.control.kind == "gate"
    }
    assert len(claimed_gates) >= 4, sorted(claimed_gates)


def test_the_gate_population_is_the_registry_less_its_non_controls():
    """A `not_a_control` row leaves the census; a script with no row stays in it.

    The second half is the fail-safe: a missing row can only widen the census, so the
    merge-path gate, which refuses the missing row, is never the only thing between a new
    gate and the residue.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "scripts").mkdir()
        (root / "config").mkdir()
        for name in ("a_gate.py", "demo.sh", "new_gate.py"):
            (root / "scripts" / name).write_text("")
        (root / "config" / "gates.toml").write_text(
            '[[script]]\npath = "scripts/a_gate.py"\nstages = [1]\nci = []\nselftest = false\n'
            '[[script]]\npath = "scripts/demo.sh"\nstages = []\nci = []\nselftest = false\n'
            'not_a_control = "a demo runner"\n'
        )
        identities = {c.identity for c in _controls.gate_controls(root)}
    assert identities == {"gate#scripts/a_gate.py", "gate#scripts/new_gate.py"}, identities


def test_every_registry_non_control_is_outside_the_census():
    """The live registry's `not_a_control` rows and the census agree, row for row."""
    excluded = {f"gate#{path}" for path in _gates.not_controls(_gates.load())}
    assert excluded, "the registry marks nothing as not a control; the marker went dark"
    gates = {identity for (_, identity) in INDEX if identity.startswith("gate#")}
    assert not excluded & gates, sorted(excluded & gates)
    assert gates, "the census found no gate at all"


def test_a_measurements_own_argv_claims_its_controls():
    """A `measured` unit declares no battery, and its protocol still selects controls.

    ADR-MCPRE-068 §4.1 gives a measured unit a protocol and an apparatus control instead of
    `tested_symbols`. A census reading only `tested_symbols` reports the controls the
    measurement RUNS as claimed by nothing — and would invite a `not-evidence` reason to be
    written about a measurement's own apparatus.
    """
    selected = {
        claim.control.identity
        for claim in REPORT.claims
        if claim.selector.startswith("measured-argv:")
    }
    assert selected, "no measurement argv resolved to a control; the join went dark"
    assert any("the_measurement_moves_when_the_scanned_set_shrinks" in s for s in selected)


def test_every_control_kind_is_non_empty():
    """A kind declared in `KINDS` and enumerated as zero is a discovery path that broke.

    The kinds are the census's own vocabulary; one of them reporting nothing over a tree
    that holds thousands of controls is the ADR-069 §2.1 defect returning under a new name.
    """
    counts = REPORT.by_kind(CONTROLS)
    empty = sorted(kind for kind, count in counts.items() if count == 0)
    assert not empty, f"kind(s) enumerated as zero: {empty}"


def test_the_measurement_is_project_scoped():
    """Two crates may hold the same selector, so identity alone cannot be the join key.

    Asserted on the SHAPE — every control carries a project, and a registry-carried one
    carries the empty project deliberately — rather than on a pair that happens to collide
    today, which would stop testing anything the moment one of them was renamed.
    """
    assert all(isinstance(control.project, str) for control in CONTROLS)
    carried = {control.kind for control in CONTROLS if control.project == ""}
    assert carried == {"structural", "mutation", "measurement", "gate"}, carried


def test_the_enumerator_is_deterministic():
    """Two runs over one tree produce the same list, so a report can be diffed."""
    again = _controls.all_controls()
    assert [c.identity for c in again] == [c.identity for c in CONTROLS]


def test_a_modified_describe_block_still_names_its_suite():
    """`describe.runIf(expr)("title", …)` nests its cases, and the census must see it.

    A suite the scanner misses does not remove its cases — they are enumerated under the
    WRONG reported name, which is worse than losing them: the identity joins to nothing, and
    a registration written against it would select a case vitest never reports. The live
    instance is the TypeScript end-to-end suite, whose cases ADR-069 dispositions.
    """
    live = (
        "sdk/typescript",
        "vitest#test/transport_e2e.test.ts > McpReHttpTransport (live) > "
        "fails closed on an unsigned response",
    )
    assert live in INDEX, "the live e2e suite moved; retarget this control"


def test_a_doctest_carries_its_fence_mode():
    """ADR-MCPRE-068 §4.1: a compile refusal is not behavioural evidence.

    The census records the mode so that a registration campaign cannot register a
    `compile_fail` example as `tested` evidence without the report saying what it is.
    """
    doctests = [c for c in CONTROLS if c.kind == "rust-doctest"]
    assert doctests
    assert all(control.note for control in doctests)
    assert any("compile-fail" in control.note for control in doctests)


def test_a_test_attribute_with_arguments_is_a_test():
    """`#[tokio::test(flavor = "multi_thread")]` declares a test as surely as the bare form.
    A census that matched only `#[tokio::test]` saw none of them."""
    tests = [
        "    #[test]",
        "    #[tokio::test]",
        '    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]',
        "    #[tokio::test(start_paused = true)]",
    ]
    not_tests = ["    #[testing]", "    #[test_case(1)]", "    #[cfg(test)]", "    // #[test]"]
    assert all(TEST_ATTR.match(line) for line in tests)
    assert not any(TEST_ATTR.match(line) for line in not_tests)


def test_a_crate_root_is_named_under_the_package_that_holds_it():
    """A target in another package compiling the same root must not re-home the crate.

    The Verus non-vacuity probe lives in `//mcp-re-http-profile/verus_probe` and compiles
    `mcp-re-http-profile/src/lib.rs`. Its label sorts before `//mcp-re-http-profile:…`, and
    when label order picked the package every http-profile test selector stopped resolving.
    """
    rows = {
        "//pkg/probe:p": {"root": "pkg/src/lib.rs", "package": "pkg/probe", "kind": "verus_verify"},
        "//pkg:lib": {"root": "pkg/src/lib.rs", "package": "pkg", "kind": "rust_library"},
        "//pkg:test": {"root": "pkg/src/lib.rs", "package": "pkg", "kind": "rust_test"},
    }
    real = _rust_targets.table
    _rust_targets.table = lambda: rows
    try:
        assert _rust_targets.crate_roots()["pkg/src/lib.rs"]["package"] == "pkg"
    finally:
        _rust_targets.table = real
    live = _rust_targets.crate_roots()
    misplaced = sorted(root for root, entry in live.items() if not _rust_targets._holds(entry["package"], root))
    assert not misplaced, misplaced
