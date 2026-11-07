# SPDX-License-Identifier: Apache-2.0
"""The plane classification, the reviewed exclusions and the recorded ownership verdicts."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
SRC = REPO / "mcp-re-proxy" / "src"
sys.path.insert(0, str(REPO / "tools" / "verification"))

# --- planes -------------------------------------------------------------------------
#
# `runtime-state` exists because of the classification failure above: config_snapshot is
# the ADR-MCPRE-051 §6 hot-reload snapshot the serve loop re-reads PER CONNECTION, and
# runtime_state is ADR-MCPRE-057 §3's lifecycle-as-a-value, which lifecycle_purity_gate
# verifies depends on no production module. Neither is startup machinery.

PLANES: dict[str, list[str]] = {
    "startup": [
        "main", "app", "cli", "startup_plan", "startup_posture",
        "serving_capabilities", "delegated_wiring",
    ],
    "runtime-state": ["config_snapshot", "runtime_state"],
    "serving": [
        "async_serve", "async_fleet", "async_inner", "http_inner", "http_profile_serve",
        "http_profile_dispatch", "request_stages", "exchange_state", "stage_timers",
        "managed_worker", "control_runtime", "materialized_runtime",
        "materializing_runtime",
    ],
    "replay": [
        "async_replay", "shared_replay", "replay_plane", "replay_tier",
        "async_redis_store", "async_etcd_store", "redis_store", "etcd_store",
        "continuation_store", "redis_continuation_store", "admission_source",
        "redis_admission_source",
    ],
    "trust": [
        "trust_plane", "trust_cache", "trust_epoch", "live_trust", "push_trust",
        "reloading_trust", "client_revocation", "revocation_tier", "ocsp",
        "trust_document", "revocation_resolver",
    ],
    "signing": [
        "signing_plane", "key_source", "kms_keysource", "kms_endpoint_policy",
        "aws_kms_keysource", "gcp_kms_keysource", "aws_sigv4", "aws_sts",
        "pkcs11_keysource", "pkcs11_native", "delegated_response_signer",
        "delegated_server_signer",
    ],
    "tls": ["tls", "tls_plane", "tls_auth_epoch", "delegated_tls", "transport"],
    "evidence": ["audit_sink", "transparency", "retained_evidence"],
    "time": ["clock"],
}
PLANE_OF = {m: p for p, ms in PLANES.items() for m in ms}

# Composition-owning planes. An edge INTO one of these from a runtime plane is the thing
# the architecture objective forbids, unless what crosses is a value or type the root
# legitimately produced.
COMPOSITION = {"startup"}

# Reviewable exclusions. Each states WHY the edge is legitimate, so the exclusion itself
# can be argued with rather than silently trusted.
LEGITIMATE: dict[tuple[str, str], str] = {
    ("replay_plane", "startup_plan"):
        "ReplayPlan is a VALUE the composition root computes once and hands down. "
        "Handing a plan to the component that executes it is what a composition root "
        "is for; driving this to zero would be metric gaming.",
    ("materialized_runtime", "app"):
        "serve_fleet is COMPOSITION: it resolves --bind, builds FleetConfig from the "
        "config, and constructs the per-core handler. Turning configuration into a "
        "running fleet is the root's job, not a service hidden inside it.",
}

# Why a target's ownership is wrong, and who should own it instead. Recorded per TARGET
# SYMBOL rather than per edge, because the same misplaced item explains several edges.
MISPLACED_OWNERSHIP: dict[str, tuple[str, str]] = {
    "load_trust": (
        "reads and assembles the trust store — a trust-plane responsibility the parser "
        "happens to host because the command line was its first caller",
        "the trust plane, with the CLI calling it like any other consumer",
    ),
    "load_trust_request_signers": (
        "same as load_trust, for the request-signer key set",
        "the trust plane",
    ),
    "build_revocation_resolver_with_channel": (
        "constructs the revocation resolver and its update channel; a revocation "
        "concern, not an argument-parsing one",
        "the trust plane",
    ),
    "load_client_crls": (
        "reads client CRLs off disk for the TLS plane; the parser owns it only because "
        "the paths arrive as flags",
        "the TLS plane, taking already-validated paths",
    ),
    "DeploymentRequest": (
        "the raw parsed-configuration type, consumed directly by runtime planes so they "
        "depend on the parser's data shape rather than on their own inputs",
        "a validated-configuration/domain type the planes own, with the parser producing it",
    ),
    "ValidatedDeployment": (
        "as DeploymentRequest; the validated form still lives in the parser module",
        "a domain configuration type outside the parser",
    ),
    "DelegatedSigningWiring": (
        "the delegated-signing wiring value, defined in a startup module and consumed by "
        "the signing plane at runtime",
        "the signing plane, if the value is its own; startup if it is genuinely composed",
    ),
    "ProdDelegatedRotor": (
        "as DelegatedSigningWiring", "the signing plane"),
    "build_delegated_signing": (
        "constructs the delegated signer; construction from validated inputs is a "
        "signing-plane responsibility",
        "the signing plane",
    ),
}
