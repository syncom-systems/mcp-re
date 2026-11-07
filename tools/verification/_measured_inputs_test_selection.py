# SPDX-License-Identifier: Apache-2.0
"""What a unit's test evidence is made of: the build configuration, the whole-crate cone of a formal unit, the effective test selection and its sources, and the test and mutation lanes' own instruments."""

from __future__ import annotations

from _fingerprint import MUTATION_LANE_INPUTS
from _measured_inputs_support import (
    UNITS,
    components,
    measure,
)
from _mutation import load_probes


# --- no component is a constant -----------------------------------------------


def test_no_component_is_a_sentinel():
    """A constant compares equal on every run. Three components were recorded as the
    literal string "unimplemented" while the module documented them as read UNKNOWN and
    therefore dirty — two whole fail-closed inputs that were inert."""
    for unit_id in UNITS:
        for name, value in components(unit_id).items():
            assert value != "unimplemented", f"{unit_id}.{name}"


def test_the_build_configuration_is_measured_and_names_the_lockfile():
    """A dependency swap, a lockfile bump or a toolchain pin change alters what a theorem is
    about without touching the source a unit declares. Bazel builds the crate, so its
    inputs are Bazel's: the module (the toolchain pin), the crate lock, the package's BUILD."""
    build = components("http_profile.freshness_window")["build_configuration"]
    assert "MODULE.bazel" in build
    assert "bazel/crates.lock" in build
    assert "mcp-re-http-profile/BUILD.bazel" in build
    assert all(digest.startswith("sha256:") for digest in build.values())


# --- the fingerprint covers the cone the LANE measures ------------------------


def test_a_formal_units_fingerprint_covers_the_whole_verified_crate():
    """The crate's `verus_verify` target verifies the crate, not the four files the unit
    lists. `check_params` quantifies over `SignatureParams`, defined in sigbase.rs, which no
    unit declares: editing it changed what the theorem says while every component stayed
    identical and the graph answered FRESH."""
    source = components("http_profile.freshness_window")["source_inputs"]
    assert "mcp-re-http-profile/src/sigbase.rs" in source
    assert "mcp-re-http-profile/src/verify/floor/params.rs" in source


def test_the_proof_dependency_closures_manifests_are_measured_too():
    """R9-C039 / R9-C040. `proof_dependencies` digests the SOURCE of the crates the prover
    compiles alongside this one, and nothing digested their manifests — so the `verify`
    feature could stop travelling down the closure, or a dependency of a dependency could be
    swapped, and the unit still derived FRESH over a prover run that had checked something
    else. The source of a crate and the manifest that decides what that crate IS are the
    same input to this question."""
    build = components("http_profile.freshness_window")["build_configuration"]
    assert "mcp-re-core/BUILD.bazel" in build, build
    assert "mcp-re-http-profile/BUILD.bazel" in build
    # And a V0 unit is not given the closure: its evidence is not a prover run, so a
    # dependency's BUILD file it never compiles against must not dirty it.
    assert "mcp-re-core/BUILD.bazel" not in components("proxy.runtime_lifecycle")["build_configuration"]


def test_a_formal_units_proof_dependencies_reach_the_verified_dependency_closure():
    """The `verify` feature travels down the path-dependency closure, so the prover checks
    mcp-re-core as part of the run an http-profile unit claims."""
    deps = components("http_profile.freshness_window")["proof_dependencies"]
    assert "mcp-re-core/src/time/mod.rs" in deps
    assert not any(path.startswith("mcp-re-http-profile/") for path in deps)


def test_an_ordinary_unit_is_not_given_a_whole_crate_cone():
    """A V0 unit's evidence is not a whole-crate prover run, so its fingerprint must not
    claim one — that would report the unit dirty for unrelated crate churn."""
    source = components("proxy.runtime_lifecycle")["source_inputs"]
    assert list(source) == ["mcp-re-proxy/src/runtime_state.rs"]


def test_the_effective_test_selection_is_measured_not_only_its_uri():
    """A `test://` URI is a LABEL. Until encoding v4 it was the only test component, so a
    battery could fall from 67 declared controls to 5 — or move to another target — with the
    URI, and therefore the fingerprint, unchanged."""
    unit_id = "http_profile.request_floor_result"
    selection = components(unit_id)["test_selection"]
    # The unit's paths span two crates, so there is no single project — and none is
    # needed: each target names its own package, and each is recorded with its row.
    assert selection["project"] is None
    assert "//mcp-re-http-profile:proof_path_test" in selection["targets"]
    # COMPARED AGAINST THE REGISTRY rather than against a magnitude. The original assertion
    # was `> 50 symbols`, chosen when this fixture was `http_profile.verifier_results` — one
    # unit carrying 73 controls for ten propositions, which the ADR-MCPRE-068 Phase-1 split
    # replaced with ten units. A count is the wrong invariant anyway: it passes a battery that
    # swapped every member. What the component must hold is THIS unit's declared symbols.
    assert set(selection["symbols"]) == set(UNITS[unit_id]["tested_symbols"])
    assert (
        "//mcp-re-http-profile:proof_path_test#keyid_swap_to_another_trusted_key_fails_the_signature"
        in selection["symbols"]
    )


def test_dropping_a_declared_control_moves_the_fingerprint():
    """The property the previous encoding did not have. Shrinking the battery must be
    visible, or a unit can lose its negative controls and stay FRESH."""
    unit = dict(UNITS["http_profile.request_floor_result"])
    before = measure(unit)["fingerprint"]
    unit["tested_symbols"] = unit["tested_symbols"][:5]
    after = measure(unit)["fingerprint"]
    assert before != after


def test_moving_a_battery_to_a_flavor_without_its_features_moves_the_fingerprint():
    """A feature-gated control does not fail without its feature — it does not EXIST. So a
    battery moved to a flavor compiled without the feature loses every control behind it.
    The target's features are in `test_selection` for the same reason v4 put the symbols
    there: the battery must not be able to shrink to whatever the default crate still
    contains."""
    unit = dict(UNITS["proxy.outbound_destination"])
    ext = "//mcp-re-proxy:proxy_ext_unit_test"
    assert all(s.startswith(f"{ext}#") for s in unit["tested_symbols"]), unit["tested_symbols"]
    before = measure(unit)["fingerprint"]
    unit["tested_symbols"] = [s.replace(ext, "//mcp-re-proxy:proxy_unit_test") for s in unit["tested_symbols"]]
    after = measure(unit)["fingerprint"]
    assert before != after


def test_a_credential_egress_claim_is_measured_in_the_crate_that_compiles_it():
    """The evidence-closure repair behind THM-0090. The redirect control and the
    capability's single addressing surface are behind the features that link an HTTP
    client, and the single-producer control is behind the two backends. A unit citing a
    conjunct whose control cannot compile in its own lane would be a theorem established
    through evidence one lane away from it."""
    destination = components("proxy.outbound_destination")["test_selection"]
    (features,) = [t["features"] for t in destination["targets"].values()]
    assert {"aws_kms_keysource", "gcp_kms_keysource", "online_ocsp"} <= set(features)
    assert any("binding::tests::an_agent_does_not_follow_a_redirect" in s for s in destination["symbols"])
    assert any("credential_egress::tests::" in s for s in destination["symbols"])
    endpoint = components("proxy.kms_endpoint_authority")["test_selection"]
    for target in endpoint["targets"].values():
        assert {"aws_kms_keysource", "gcp_kms_keysource"} <= set(target["features"]), target
    assert any(
        "endpoint::tests::an_endpoint_the_rule_refuses_yields_no_egress" in s
        for s in endpoint["symbols"]
    )


def test_moving_the_battery_to_another_target_moves_the_fingerprint():
    """The target decides what runs, so it decides what was measured; a fingerprint blind
    to it would let the measurement move under a standing attestation."""
    unit = dict(UNITS["http_profile.request_floor_result"])
    before = measure(unit)["fingerprint"]
    unit["tested_symbols"] = [
        s.replace("//mcp-re-http-profile:proof_path_test", "//mcp-re-http-profile:full_profile_test")
        for s in unit["tested_symbols"]
    ]
    after = measure(unit)["fingerprint"]
    assert before != after


def test_the_integration_test_sources_are_measured_not_only_their_names():
    """A control can keep its declared name and lose its body: the selector still resolves,
    the lane still reports a pass. The name is the label; the file is the evidence."""
    sources = components("http_profile.request_floor_result")["test_sources"]
    # Exactly the integration targets this unit's battery selects, and no others — see the
    # measured-not-counted note above.
    assert "mcp-re-http-profile/tests/proof_path_test.rs" in sources
    assert "mcp-re-http-profile/tests/algorithm_confusion_test.rs" in sources
    assert "mcp-re-http-profile/tests/delegation_e2e_test.rs" not in sources
    assert all(digest.startswith("sha256:") for digest in sources.values())
    # A target the unit does not select is not measured: the component is the unit's
    # evidence, not the package's test directory.
    assert "mcp-re-http-profile/tests/rfc9421_kat.rs" not in sources


def test_in_crate_selectors_are_covered_by_the_units_own_paths():
    """Selectors on a target built from a crate are deliberately absent from
    `test_sources` because they execute inside files `source_inputs` already digests. That
    is only safe because the manifest loader REFUSES a selector whose module the unit does
    not declare."""
    from _manifest import ManifestError, _validate_in_crate_selectors

    unit = {
        "paths": ["mcp-re-http-profile/src/verify.rs"],
        "tested_symbols": [
            "//mcp-re-http-profile:mcp_re_http_profile_test#rejection::tests::unbound_rejection_verifies"
        ],
    }
    try:
        _validate_in_crate_selectors("unit[0]", unit)
    except ManifestError:
        pass
    else:
        raise AssertionError("an undeclared in-crate module must be refused")

    # A file the tree does not hold is no coverage: `rejection` is a directory module.
    unit["paths"].append("mcp-re-http-profile/src/rejection.rs")
    try:
        _validate_in_crate_selectors("unit[0]", unit)
    except ManifestError:
        pass
    else:
        raise AssertionError("a path naming no file of the module tree must not cover a selector")

    unit["paths"].append("mcp-re-http-profile/src/rejection/mod.rs")
    _validate_in_crate_selectors("unit[0]", unit)

    # A module DIRECTORY resolves through any prefix of the selector's path.
    nested = {
        "paths": ["mcp-re-http-profile/src/verified_response/bound.rs"],
        "tested_symbols": [
            "//mcp-re-http-profile:mcp_re_http_profile_doc_test#verified_response::bound::VerifiedMcpResponse"
        ],
    }
    _validate_in_crate_selectors("unit[0]", nested)

    # A binary crate's tests are built from the binary the same way, so they carry the
    # identical obligation. Exempting them would put a deployable's own controls outside
    # every fingerprint component — the one place the question "does the artifact an
    # operator runs do this?" can be asked.
    deployable = {
        "paths": ["mcp-re-client/src/anchors/mod.rs"],
        "tested_symbols": ["//mcp-re-client:mcp_re_client_cli_test#startup::tests::t"],
    }
    try:
        _validate_in_crate_selectors("unit[0]", deployable)
    except ManifestError:
        pass
    else:
        raise AssertionError("an undeclared binary-crate module must be refused too")

    deployable["paths"].append("mcp-re-client/src/startup.rs")
    _validate_in_crate_selectors("unit[0]", deployable)


def test_the_test_lane_instrument_is_part_of_the_evidence_identity():
    """What a selector's target resolves to, and which ecosystem runs the battery at all, is
    decided by the lane's own code. Evidence whose measuring instrument
    changed is evidence whose meaning changed — the same argument that puts the toolchain in
    the fingerprint, and the reason #745's adapter registry joined the set rather than
    sitting beside it unmeasured."""
    lane = components("http_profile.request_floor_result")["test_lane_identity"]
    assert set(lane) == {
        "tools/verification/verify-tests",
        "tools/verification/_manifest.py",
        "tools/verification/_record_rules.py",
        "tools/verification/_ecosystems.py",
        "tools/verification/_rust_targets.py",
        # Which units are in scope: `test://` claims the lane through the catalogue.
        "tools/verification/_lanes.py",
    }
    assert all(digest.startswith("sha256:") for digest in lane.values())


def test_the_probe_set_is_measured_so_the_suite_cannot_silently_shrink():
    """`mutation://` puts the probe suite inside the attestation closure, but a closure
    over a suite that can shrink proves as little as the v3 test component did. Each probe
    entry is digested WHOLE, so softening a weakening or widening an `expect_red` moves the
    fingerprint and invalidates the standing mutation PASS."""
    unit_id = "http_profile.request_floor_result"
    probes = components(unit_id)["mutation_probes"]
    # Again the registry rather than a magnitude: every probe registered against this unit,
    # and nothing else. Before the Phase-1 split this read `> 20`, which was a property of a
    # unit that answered for ten propositions.
    registered = {pr["id"] for pr in load_probes() if pr["unit"] == unit_id}
    assert set(probes) == registered and registered
    assert all(digest.startswith("sha256:") for digest in probes.values())
    lane = components("http_profile.request_floor_result")["mutation_lane_identity"]
    assert set(lane) == set(MUTATION_LANE_INPUTS)
    assert "tools/verification/verify-mutations" in lane
