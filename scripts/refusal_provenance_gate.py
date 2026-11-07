#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refusal-provenance gate — ADR-MCPRE-066 Slice 0 (#642).

WHAT THIS PROVES, over production Rust (test regions excluded):

  1. **A refusal carries a cause, not a token.** `Refusal` has a `cause: RefusalCause`
     field and no `wire_code` FIELD. A struct that stores a rendered token has already
     thrown away which authority produced it, and no downstream check can recover that.
  2. **`RefusalCause` is closed over exactly the two authorities on this path** — `Core`
     and `Authorization`. A third arm is a design decision, not a variant.
  3. **The authorization stage hands its refusal over WHOLE.** `authorization_stage` does
     not call `.wire_code()`. This is poison pill 1: re-render there and the gate fails
     alongside the unit control that measures the same thing behaviourally.
  4. **No production site renders a token INTO a `Refusal` constructor.** The three
     constructors take `impl Into<RefusalCause>`, and no call site passes a `&'static str`
     or a `.wire_code()` result.
  5. **`PolicyError` has no route into the Core taxonomy.** No `impl From<PolicyError>`
     for `McpReError` or for `RefusalCause::Core` exists anywhere in the workspace. This is
     poison pill 2: the authorization branch must arrive at the audit boundary still
     recognizably authorization provenance, and a conversion is what would silently end
     that.
  6. **The cause algebra is exhaustive by construction.** `refusal/` carries no wildcard arm
     (`_ =>`), so a new authority or a new Core producer is a COMPILE error until it names
     its verdict, rather than silently inheriting one.

ADDED BY SLICE 1 (#644) — the provenance now has to survive one step further, into the
record itself:

  7. **A request record always states an authorization outcome.** The `Request` arm carries
     an `authorization: AuthorizationFacet`, never an `Option` and never a `NotApplicable`.
     ADR-MCPRE-066 R3: absence must have exactly one meaning — a record from before this
     slice — and an `Option` gives it two.
  8. **A response record carries none.** Authorization is request-side (R5). A response
     record does not represent a second authorization decision and must not be able to
     claim one.
  9. **The facet is PROJECTED, never assembled at the audit site.** The serving path does
     not construct an `AuthorizationFacet` variant or an `AuthorizationAttribution` literal;
     it asks the owner (`audit_facet` / `authorization_facet`). Invariant 5 / R-COMPOSE: a
     composition root that builds the facet out of parts has re-derived what an owner
     already decided.

ADDED BY SLICE 2 (#648) — the containment stops being a rule and becomes a type:

 10. **No audit rejection constructor takes a string.** `mcp-re-core/src/audit.rs` declares
     no `fn *_rejected_code(reason: &'static str)`. That was the join where two authorities'
     tokens became indistinguishable (#637); with it gone, `PolicyError -> AuditEvent.reason`
     does not typecheck, and invariant 9's producer graph is decided by the compiler rather
     than discovered by a scanner over a hand-maintained file list.
 11. **The serving path never renders a token into an audit event.** `rejection` and
     `response_rejection` take a typed `RefusalCause` and ask it for a Core verdict; neither
     passes a `wire_code()` result to an `AuditEvent` constructor.

ADDED BY THE ADR-MCPRE-059 §28 CLOSURE (THM-0081) — the provenance is worth nothing at the
sites it does not reach, so the last clause measures the SITE SET rather than a route:

 12. **Every production refusal is inside the exchange lifecycle.** Four facts, together
     total over the exits a served request can take:

     (a) the serving subtree mints no response of its own — the only construction of a
         `ServedHttpResponse` under `http_profile_serve` is inside `served`, which wraps a
         fully-built `HttpResponse` that the receipt owner produced from a `Refusal`;
     (b) `handle` answers only through its stages — every `Err` arm returns the binding the
         stage produced, and none builds a response at the exit;
     (c) the pre-exchange transport refusals are exactly the DECLARED set. `ServedHttpResponse::json`
         is the one mint of a SERVED response outside the exchange, it has exactly one production
         call site anywhere in the workspace, and that site is reached before the handler — before
         an exchange exists to be refused inside. The transport frame's other three replies are
         built at the hyper type rather than this one and are enumerated by the unit battery
         (`refusal_site_totality_test`), which can name the frame's files; this clause is the
         WORKSPACE-width half, and its job is that no fourth crate acquires a served mint;
     (d) the retry contract every refusal carries is DERIVED from the exchange machine.
         `disposition` reads `retry_semantics()` and has no wildcard arm, so a new machine
         consequence is a compile error rather than a silently inherited contract.

     This is what THM-0043 and THM-0046 do not say. They establish that the relation is
     decided everywhere and that a refusal remembers which authority reached it; neither says
     that every SITE is inside the lifecycle, and an exit answering from source position would
     satisfy both while stating a retry contract the machine never derived — the defect that
     let a refusal after a spent approval report an ordinary retry.

WHY (5) IS THE ONE THAT MATTERS. Every other check here constrains a shape that a reviewer
would notice changing. A `From<PolicyError> for McpReError` would look like a convenience,
would compile, would make every existing test pass, and would re-create the exact defect
ADR-MCPRE-066 was opened for — one taxonomy quietly absorbing another's semantics. It is
the only one of the six that a well-intentioned edit is likely to introduce.

WHAT (10) REPLACED. Slice 1 could not assert that Core's `reason` was free of foreign
tokens, because it was not: an authorization refusal's `wire_code()` still reached
`request_rejected_code`. Slice 2 deleted the constructor rather than adding a scanner for
its callers, which is why the check is the absence of a SHAPE rather than a survey of
producers. The companion claim — that no carrier mints an `mcp-re.*` token of its own — is
`//mcp-re-conformance:audit_vocabulary_guard_test`.

WHAT IT DOES NOT PROVE: that the right cause is chosen at any given site. That is the unit
controls in `refusal/cause.rs`, and the wire-compatibility controls that show Slice 0 is
observably a no-op. This gate is syntactic and its claim stops at the shape of the route.

Run:  python3 scripts/refusal_provenance_gate.py
      python3 scripts/refusal_provenance_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _refusal_provenance.config import (  # noqa: E402,F401
    CORE_AUDIT,
    DECLARED_TRANSPORT_REFUSAL_SITES,
    RECORD,
    REFUSAL,
    REPO,
    SERVED_JSON,
    SERVED_RESPONSE_OWNER,
    SERVING,
    TRANSPORT,
)
from _refusal_provenance.check import check  # noqa: E402,F401
from _refusal_provenance.cli import judge  # noqa: E402
from _refusal_provenance.selftest import selftest  # noqa: E402,F401
from _refusal_provenance.sources import (  # noqa: E402,F401
    body_of,
    body_of_variant,
    read,
    read_unit,
    workspace_rust_files,
)


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    return judge()


if __name__ == "__main__":
    sys.exit(main())
