#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Authorization-provenance gate — ADR-MCPRE-065 Slice 1 (#630).

WHAT THIS PROVES, exactly, over production Rust (test regions excluded):

  1. The authorization authority names no certificate, TLS or transport-identity route.
     `TransportIdentity`, `extract_identity`, `peer_certificates`, `x509`, `rustls`,
     `from_leaf_der` and friends may not appear in it. Peer identity reaches authorization
     as the ADR-MCPRE-064 product or not at all.
  2. **Law A-1.** The authorization authority names no MCP transport header and never asks
     whether a transport contract is enforced. `Mcp-Method`, `Mcp-Name`,
     `MCP_METHOD_HEADER`, `MCP_NAME_HEADER` and `mcp_transport` are absent from it.
  3. The action coordinate proves its own pairing: `interpret_authorization_action` asks
     the verified request itself (`covers_body`), so a body that is not the signed body
     cannot produce an inhabitant — and the comparison is not re-derived here from parts.
  4. The serving path decides exactly once: `handle` calls `authorization_stage` once,
     `authorization_stage` reaches `decide`, and `decide` reaches `authorize`.
  5. `authorize` admits its predecessors and NOTHING else. No `header`, no `leaf`, no
     `chain`, no `certificate`, no `cert`, no rival identity parameter.
  6. Both sealed products keep their representation private: no `pub` field in
     `VerifiedAuthorizationActor`, `VerifiedAuthorizationAction`, `AuthorizationRequest` or
     `AuthorizedRequestFacts`.
  7. **Dispatch is gated by the type, not by source order.** `InnerPlane::prepare` takes an
     `AuthorizedRequestBody` and is the only thing that can transmit; `ReadyForDispatch::new`
     takes the `PreparedInnerDispatch` it returns rather than bytes; that body type has
     exactly ONE producer, `release`, defined once on `AuthorizationPosture`; and the
     serving assembly calls `release` exactly once. A pipeline that dropped the decision
     would not compile at the dispatch.

     The parameter moved with #741 and the chain did not weaken. It used to be
     `ReadyForDispatch::new(AuthorizedRequestBody, ..)` with the dispatch borrowing the
     bytes back out; now the released body is CONSUMED by `prepare`, which owns the bytes it
     will send, so there is no second copy of the body for a later stage to substitute and
     no way to reach the backend except through the value a decision produced.
  8. No configuration promotes a conformance evaluator to production authority:
     `--authz reference` is still refused by Layer-A validation.
 10. **The posture that claims nothing has one producer.** `AuthorizationPosture`'s variants
     are named in production only in `decide.rs`, which builds them, and `posture.rs`, which
     projects them. Nowhere else in the authority, and nowhere in the serving path. This is
     what closes the gap the sealed body type leaves open: `NoPolicyConfigured` is a public
     variant, so possession of an `AuthorizedRequestBody` proves a decision was TAKEN and
     not that a configured policy produced it — unless nothing else can synthesize the
     posture that claims nothing.

  9. **The Mode-1 linkage form can never become Mode-2 evidence.** The candidate filter in
     `bound_decision_evidence` selects on `BindingType::OpaqueDigest`, so a
     `pdp-decision` / `reference-digest` entry — which names an external decision MCP-RE
     authenticates nothing about — is not a candidate at all, rather than a candidate that
     is rejected later.

WHY (5) IS THE ONE THAT MATTERS. Law A-1 is not enforced by a check that could be deleted;
it is enforced by the ABSENCE OF A PARAMETER through which a header could enter. That is a
property of a signature, and a signature is what a future edit widens first — "just pass the
headers too, we already have them" reintroduces the defect without touching a single check,
and every behavioural control stays green because each still measures a true thing about a
correctly-composed value.

WHAT IT DOES NOT PROVE: that the decision is right. That is the controls in
`tests/integration_async/authorization_serving_test.rs`, which drive real signed requests
whose covered routing header disagrees with the body they also signed. This gate is
syntactic and its claim stops at the shape of the route.

Run:  python3 scripts/authorization_provenance_gate.py
      python3 scripts/authorization_provenance_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _authorization_provenance.config import (  # noqa: E402,F401
    AUTHORITY_DIR,
    PLANE,
    REPO,
    SERVING,
    STAGES,
    VALIDATION,
)
from _authorization_provenance.authority import check_authority, check_posture_producers  # noqa: E402,F401
from _authorization_provenance.cli import judge  # noqa: E402
from _authorization_provenance.dispatch import check_dispatch, check_validation  # noqa: E402,F401
from _authorization_provenance.rusttext import (  # noqa: E402,F401
    body_of,
    signature_re,
    struct_body,
    without_comments,
)
from _authorization_provenance.selftest import selftest  # noqa: E402,F401
from _authorization_provenance.serving import check_serving  # noqa: E402,F401
from _authorization_provenance.sources import Anchored, authority_sources, check, read  # noqa: E402,F401


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    return judge()


if __name__ == "__main__":
    sys.exit(main())
