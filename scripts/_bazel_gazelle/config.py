# SPDX-License-Identifier: Apache-2.0
"""The audited allowlist and the diff-line patterns the drift classifier reads."""

from __future__ import annotations

import re

# --- Allowlist: intentional generated-vs-hand-maintained exceptions ----------
#
# A gazelle-proposed NEW target whose name is here is NOT counted as drift. Every
# entry states WHY it is exempt. Keep this list tight — it is the audited seam
# between "gazelle may add this" and "a human decided this stays as-is."

# Naming collisions: gazelle names a crate's lib/bin/crate-test after the Cargo
# package name (with dashes) or `<crate>_test`; the repo already ships the SAME
# unit under a hand-chosen target name (e.g. `mcp_re_proxy_cli`, `proxy_unit_test`).
# Adopting gazelle's name would duplicate, not add coverage.
ALLOW_NAMING_COLLISION = {
    "mcp-re-conformance",            # == conformance lib/bin, hand-named
    "mcp-re-proxy",                  # == :mcp_re_proxy_cli (bin over src/main.rs)
    # == :mcp_re_auditor_cli, the bin over src/bin/mcp-re-auditor.rs. Hand-named for the
    # same reason as the proxy CLI: every executable in this repo ships under a
    # `_cli`-suffixed target, and adopting gazelle's package-derived name would duplicate
    # the unit rather than add coverage.
    "mcp-re-auditor",
    "mcp-re-client",                 # == :mcp_re_client_cli (bin over src/main.rs)
    "mcp_re_proxy_test",             # == :proxy_unit_test (crate=:mcp_re_proxy)
    "mcp-re-client_test",            # == :mcp_re_client_cli_test (crate=:mcp_re_client_cli)
    "emit_mtls_fixtures",          # == hand-named fixture-emitter bin
    # The consolidated proxy suites: a cargo test target is named for its directory
    # (`tests/integration_async/`), while every nt_rust_test in this repo ends in
    # `_test`. Same unit, two naming conventions — Bazel ships :integration_test,
    # :integration_async_test, :integration_ext_test and :integration_live_test over
    # exactly these sources, so adopting gazelle's name would duplicate a target rather
    # than add coverage.
    "integration",
    "integration_async",
    "integration_ext",
    "integration_live",
}

# HITL / live-cloud: `#![cfg(feature="…kms…")]`; the live cases are `#[ignore]`,
# run ONLY in the manual/nightly live-infra lane against real AWS/GCP KMS. A
# generated Bazel target would compile empty (misleading) or attempt real cloud
# calls in CI. Cargo-only. Some ({aws,gcp}_kms_http_profile_live_test,
# {aws,gcp}_kms_delegated_signing_live_test) also carry a hermetic
# local-key offline lane; those modules are compiled into
# :integration_live_test, where the offline lanes run and the live ones stay ignored.
#
# NOT allowlisted, and deliberately so: `aws_irsa_web_identity_test`. It drives the
# IRSA exchange against a LOCAL fake STS over loopback, so it needs no cloud and no
# `#[ignore]` — it is a real Bazel target and runs on every `bazel test //...`.
ALLOW_HITL_LIVE = {
    "aws_kms_live_test",
    "aws_kms_delegated_required_live_test",
    "aws_kms_delegated_signing_live_test",
    "aws_kms_http_profile_live_test",
    "aws_kms_delegated_tls_live_test",
    # The AWS twin of gcp_kms_root_rotation_live_test: two DISPOSABLE keys,
    # self-provisioned and destroyed by docs/security/aws-kms-root-rotation.sh.
    "aws_kms_root_rotation_live_test",
    "gcp_kms_live_test",
    "gcp_kms_delegated_tls_live_test",
    "gcp_kms_http_profile_live_test",
    "gcp_kms_delegated_signing_live_test",
    "gcp_kms_delegated_required_live_test",
    # ADR-MCPRE-052 §I: live Cloud KMS trust-anchor rotation across two DISPOSABLE
    # KMS key versions (self-provisioned by docs/security/gcp-kms-root-rotation.sh).
    "gcp_kms_root_rotation_live_test",
}

# Non-hermetic guards: cargo tests that assert an invariant of the git WORKING
# TREE itself (they shell out to `git` over the checkout). Bazel runs tests in a
# hermetic sandbox with no `.git` and no working tree, so a generated target
# would fail spuriously. These are structurally cargo-lane-only, not "not yet
# wired" — do NOT move them to a Bazel target.
# Empty. This held "no_tracked_secrets", allowlisted as a permanent cargo-only
# guard — but no such test existed anywhere in the tree (the crate it named,
# `mcp-re-walkthrough`, is not a workspace member), so the entry excused a target
# that could never run. The guard it described now exists for real as
# `scripts/tracked_secrets_gate.py`, a python CI gate that reads the git tree
# directly, so it needs no cargo-lane exemption here.
ALLOW_NON_HERMETIC: set[str] = {
    # mcp-re-test-paths' unit tests check the CARGO-side fallback table against the
    # SOURCE TREE: that every workspace-relative path it names still exists, and that
    # an unknown key is refused. Both resolve through `workspace_root()`, which reads
    # `CARGO_MANIFEST_DIR` and walks up for the `[workspace]` manifest. Under the
    # Bazel sandbox there is no manifest dir and no source tree, so the tests would
    # panic on the environment rather than measure the table. The Bazel half of the
    # same mapping needs no test: `$(rlocationpath f)` cannot resolve a file that is
    # not in the tree, so the BUILD analysis already refuses what these assert.
    "mcp_re_test_paths_test",
}

# Test-support crates with their own detached `[workspace]`: under cargo the consuming
# test builds them on demand (a nested `cargo build`). gazelle would generate a target
# in the crate's own directory; Bazel builds it in the consumer's package instead.
ALLOW_CARGO_ONLY_FIXTURE = {
    # mcp-re-proxy/tests/mock-pkcs11: hermetic mock PKCS#11 provider `cdylib` dlopen'd
    # by pkcs11_keysource_e2e_test; under Bazel it is //mcp-re-proxy:mock_pkcs11.
    # See [[no-onprem-hsm-custody]].
    "mock_pkcs11",
}

# Upstream prover reproducers: a minimal crate that reproduces a TOOLCHAIN bug and is
# sent to that toolchain's maintainers. It is not workspace source and not a test of
# this repo — it carries its own detached `[workspace]`, is absent from the root
# `members` list, and depends on prover crates (vstd, verus_builtin) that are not in
# the Bazel crate universe. Cargo does not build it either, so unlike every other
# category here there is no lane whose coverage a Bazel target would restore.
# `tools/verification/check-assumptions` excludes `verification/reproducers/` for the
# same reason.
ALLOW_UPSTREAM_REPRODUCER = {
    # verification/reproducers/verus-ice-closure-return-type: reproduces a Verus ICE on
    # a closure return type; the measured prover ceiling it documents is cited in
    # verification/baseline/wp2-http-profile-triage.md.
    "verus_ice_closure_return_type",
}

# Tracked known drift: genuine missing Bazel targets whose Bazel wiring needs a
# dedicated fixture/runfile bridge. Filed as issues; allowlisted so the gate is
# GREEN-but-honest until each is wired, and NEW untracked drift still fails.
# Remove an entry when its target lands. (Now empty — the gate's first finds
# [continuation_roundtrip_test, continuation_driving_test, draft02_vectors_test]
# and then sdk_driver_matrix (MCPS-77) are all real Bazel targets;
# no_tracked_secrets moved to ALLOW_NON_HERMETIC as a permanent cargo-only guard.)
ALLOW_TRACKED_DRIFT = {
    # The HTTP-profile proof-front EXAMPLES (not tests): a runnable RFC 9421 client
    # + proxy pair that drive a real external FastMCP Streamable-HTTP backend over
    # the wire. They cannot be a hermetic Bazel test (they need the external FastMCP
    # process + a bound port); they run via tools/http_profile_proof.sh. Will be
    # Bazel-wired if/when the HTTP persona-ladder walkthrough is made hermetic.
    # The saturation rig and the replay-store bench: MEASUREMENT tools, not tests. Each
    # needs a Docker Redis primary+2-replica fleet, several co-operating processes, and a
    # QUIET BOX to mean anything — under the Bazel sandbox they would either fail to
    # start or, worse, produce a number measured against contended CPU and report it as
    # a result. They are driven by scripts/saturation_rig.sh and
    # scripts/runtime_topology_sweep.sh. Structurally non-hermetic, not "not yet wired".
    "saturation_rig": "ADR-MCPRE-051 §1 — measurement binary; needs Docker Redis + a quiet box",
    "saturation_loadgen": "ADR-MCPRE-051 §1 — measurement binary; load generator process for the rig",
    "saturation_backend": "ADR-MCPRE-051 §1 — measurement binary; inner backend process for the rig",
}

ALLOWLIST = (
    ALLOW_NAMING_COLLISION
    | ALLOW_HITL_LIVE
    | ALLOW_NON_HERMETIC
    | ALLOW_CARGO_ONLY_FIXTURE
    | ALLOW_UPSTREAM_REPRODUCER
    | set(ALLOW_TRACKED_DRIFT)
)

# A quoted Bazel label at line start (first-party //, third-party @crates_mcp_re//:,
# or local :). Captures the bare label value so trailing commas AND inline
# comments (e.g. `"//x:y",  # #220 …`) don't defeat reorder-cancellation.
LABEL_TOKEN_RE = re.compile(r'^"((?://|@|:)[^"]+)"')
NEW_TARGET_RE = re.compile(r"^(nt_rust_\w+)\($")
NAME_RE = re.compile(r'^name = "([^"]+)",')

# Plain-form crate names whose `use` is satisfied by a KEPT feature-flavor dep
# (MCPS-69): gazelle's `resolve` points `use mcp_re_host` at `:mcp_re_host`, but the
# target already carries `:mcp_re_host_test_fixtures  # keep`, so a proposed plain
# edge is a flavor artifact, not a missing edge.
FLAVOR_PLAIN = {
    "mcp_re_host",
    "mcp_re_proxy",
    "mcp_re_transport",
    # ADR-MCPRE-052: the pre-052 fixture chain. Each of these publishes a `_pre052`
    # flavor beside its plain target, so a proposed plain edge on a target that already
    # carries the flavor edge is the same artifact this set exists for.
    "mcp_re_http_profile",
    "mcp_re_client_core",
    "mcp_re_client_proxy",
}
ATTR_OPEN_RE = re.compile(r"^\w+ = \[$")  # e.g. `deps = [`, `srcs = [`
