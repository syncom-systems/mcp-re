# SPDX-License-Identifier: Apache-2.0
"""What the gate reads and the vocabulary it forbids: paths, names, links and sealed products."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools" / "verification"))

#: The authorization authority. Every file of it, because the claim is about the AUTHORITY,
#: not about one module of it — a route added next door would otherwise be invisible.
AUTHORITY_DIR = "mcp-re-proxy/src/authorization"

#: The serving path that consults it, and the machine that orders the decision.
#:
#: A DIRECTORY, read whole. MCPRE-175 split the assembly into one module per region of the
#: exchange, so `authorization_stage` and the function that orders it moved out of
#: `mod.rs`; a gate still reading that one file counted zero calls, which is the shape this
#: gate exists to refuse. The claim is about the serving PATH, and its closure follows the
#: owner subtree.
SERVING = "mcp-re-proxy/src/http_profile_serve"

#: The function that orders the pre-admission region, and therefore the one place the
#: authorization decision is sequenced. `handle` orders the REGIONS; this orders the
#: decisions inside the free one. The chain the gate checks is
#: `handle` -> `REGION_ASSEMBLY` -> `authorization_stage` -> `decide`, each exactly once.
REGION_ASSEMBLY = "admit_request"
VALIDATION = "mcp-re-proxy/src/config_state/validation/residue.rs"

#: Certificate / TLS / transport-identity vocabulary. Peer identity reaches authorization as
#: `RequestPeerBindingFacts` or not at all (ADR-MCPRE-065 §3).
RAW_PEER_ROUTE = (
    "TransportIdentity",
    "extract_identity",
    "interpret_identity",
    "from_leaf_der",
    "resolve_identity_from_leaf",
    "peer_certificates",
    "x509",
    "rustls",
)

#: Transport routing hints, and the contract that would make them agree with the body.
#: Law A-1: none of these is authorization authority, and correctness must not depend on
#: whether the contract is enforced.
TRANSPORT_HINTS = (
    "Mcp-Method",
    "Mcp-Name",
    "MCP_METHOD_HEADER",
    "MCP_NAME_HEADER",
    "mcp_transport",
)

#: `(file, function, what its body must reach)`. FILE-SCOPED on purpose: the authority now
#: has more than one `decide`, and a gate that searched the concatenated source would measure
#: whichever it found first — reporting a true fact about the wrong function.
LINKS = (
    ("verified_action.rs", "interpret_authorization_action", "covers_body"),
    ("serving.rs", "decide", "authorize"),
    ("relation.rs", "decide", "verify_authorization_decision"),
    ("evidence.rs", "bound_decision_evidence", "verify_pdp_decision_binding"),
    # The Mode-1 / Mode-2 split, structurally. The candidate filter must name the EVIDENCE
    # form: a `reference-digest` entry names an external decision MCP-RE authenticates
    # nothing about, and it must not be selectable and then rejected — it must never enter.
    ("evidence.rs", "bound_decision_evidence", "BindingType::OpaqueDigest"),
)

#: Every sealed product of this authority, and the rule: a private representation.
SEALED = (
    "VerifiedAuthorizationActor",
    "VerifiedAuthorizationAction",
    "AuthorizationRequest",
    "AuthorizedRequestFacts",
)

#: The posture and where its variants may be named in production.
#:
#: `decide.rs` BUILDS them and is the only operation entitled to; `posture.rs` OWNS them and
#: projects them. A third file naming a variant is either a second producer — which would let
#: a serving path release a body under the posture that claims nothing, on a deployment where
#: a policy is configured — or a consumer destructuring what it should be asking for.
POSTURE = "AuthorizationPosture"
POSTURE_VARIANTS = ("NoPolicyConfigured", "Authorized")
POSTURE_SITES = ("decide.rs", "posture.rs")

#: The type that gates the dispatch, its single producer, and the two links it passes
#: through.
#:
#: This is the enforcement, and it is stronger than an ordering check: transmitting consumes
#: a `ReadyForDispatch`, that state carries the capability `InnerPlane::prepare` returns,
#: `prepare` takes an `AuthorizedRequestBody` by value, and the only way to obtain one is an
#: authorization decision releasing it. A pipeline that dropped the stage does not become a
#: subtly weaker proxy that still compiles.
DISPATCH_BODY = "AuthorizedRequestBody"
RELEASE = "release"
STAGES = "mcp-re-proxy/src/request_stages.rs"

#: The capability the ready state carries, and the one function that produces it from a
#: released body. Two links rather than one since #741, and both are checked: a
#: `ReadyForDispatch` built from anything else, or a `prepare` that would accept bare bytes,
#: each restores a route to the backend that no decision authorized.
DISPATCH_CAPABILITY = "PreparedInnerDispatch"
PREPARE = "prepare"
PLANE = "mcp-re-proxy/src/http_profile_serve/inner_plane.rs"

#: A parameter through which a header, a certificate or a rival identity could enter.
FORBIDDEN_PARAM = re.compile(
    r"\b(header|headers|leaf|leaf_der|der|chain|cert|certificate|cert_der|identity|"
    r"peer_identity|transport)\b"
)
