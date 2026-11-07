# SPDX-License-Identifier: Apache-2.0
"""The selftest's scenarios: each undoes one claim in a fixture, and the claim's clause must trip."""

from __future__ import annotations

from dataclasses import dataclass

from _refusal_provenance.config import CORE_AUDIT, RECORD, REFUSAL, SERVING

SERVED_STUB = "fn served(r: HttpResponse) -> ServedHttpResponse { ServedHttpResponse { s: 1 } }\n"


@dataclass(frozen=True)
class Scenario:
    """Override `files`; at least `expected` problems must follow, one carrying `marker` if given.

    The marker, where a case declares one: the fixture must trip the clause it was written
    for. Counting problems alone lets a fixture that breaks four unrelated shapes pass as
    evidence for a clause it never reached.
    """

    name: str
    files: dict[str, str]
    expected: int = 1
    marker: str | None = None


def cause_scenarios() -> list[Scenario]:
    return [
        Scenario(
            "the Refusal keeps a rendered token field",
            {REFUSAL[0]: "pub(crate) struct Refusal {\n    wire_code: &'static str,\n}\n"},
        ),
        Scenario(
            "the authorization stage renders its refusal again (poison pill 1)",
            {SERVING: "fn authorization_stage(&self) -> u8 {\n"
                      "    self.authorization.decide().map_err(|r| Refusal::new(r.wire_code(), 403))\n}\n"},
        ),
        Scenario(
            "a PolicyError conversion into the Core taxonomy appears (poison pill 2)",
            {REFUSAL[1]: "impl From<PolicyError> for McpReError {\n"
                         "    fn from(_e: PolicyError) -> McpReError { todo!() }\n}\n"},
        ),
        Scenario(
            "a PolicyError is placed in the Core arm",
            {REFUSAL[1]: "fn f() { RefusalCause::Core(PolicyError::AuthorizationScopeDenied) }\n"},
        ),
        Scenario(
            "the cause algebra grows a wildcard arm",
            {REFUSAL[1]: "fn wire_code(&self) -> &'static str {\n    match self {\n"
                         "        _ => \"mcp-re.missing_envelope\",\n    }\n}\n"},
        ),
        Scenario(
            "a call site renders a token into a constructor",
            {SERVING: 'fn f() { Refusal::preflight("mcp-re.missing_envelope", 400) }\n'},
        ),
    ]


def record_scenarios() -> list[Scenario]:
    return [
        Scenario(
            "the request record's facet becomes optional (R3)",
            {RECORD: "pub enum AuditSubject {\n"
                     "    Request {\n        event: AuditEvent,\n"
                     "        authorization: Option<AuthorizationFacet>,\n    },\n"
                     "    Response {\n        event: AuditEvent,\n    },\n}\n"},
        ),
        Scenario(
            "a response record acquires an authorization coordinate (R5)",
            {RECORD: "pub enum AuditSubject {\n"
                     "    Request {\n        event: AuditEvent,\n"
                     "        authorization: AuthorizationFacet,\n    },\n"
                     "    Response {\n        event: AuditEvent,\n"
                     "        authorization: AuthorizationFacet,\n    },\n}\n"},
        ),
        Scenario(
            "the serving path assembles the facet instead of projecting it",
            {SERVING: "fn f() { self.audit(AuditSubject::request(e, "
                      "AuthorizationFacet::Refused(x))) }\n"},
        ),
        Scenario(
            "a string-taking audit rejection constructor comes back (invariant 8)",
            {CORE_AUDIT: "impl AuditEvent {\n"
                         "    pub fn request_rejected_code(reason: &'static str) -> Self { todo!() }\n"
                         "}\n"},
        ),
        Scenario(
            "the serving path renders a token into an audit event (invariant 9)",
            {SERVING: "fn f() { self.audit(AuditEvent::request_rejected_code(cause.wire_code())) }\n"},
        ),
    ]


def lifecycle_scenarios() -> list[Scenario]:
    return [
        Scenario(
            "the serving path mints a response at the exit (12a)",
            {SERVING: "fn served(resp: HttpResponse) -> ServedHttpResponse {\n"
                      "    ServedHttpResponse { status: resp.status }\n}\n"
                      "fn oops() -> ServedHttpResponse {\n"
                      "    ServedHttpResponse { status: 500, headers: vec![], body: vec![] }\n}\n"},
            marker="mints a response outside `served`",
        ),
        Scenario(
            "an `Err` arm in `handle` builds its own answer (12b)",
            {SERVING: SERVED_STUB
                      + "async fn handle(&self) -> ServedHttpResponse {\n"
                        "    match self.verify_stage() {\n"
                        "        Ok(v) => v,\n"
                        "        Err(_rejection) => return self.responses.json(500),\n"
                        "    }\n}\n"},
            marker="does something other than return the binding",
        ),
        Scenario(
            "an undeclared pre-exchange refusal site appears (12c)",
            # Keyed on a FILE, not on the `RECORD` subtree: clause 12c rides the whole-workspace
            # walk, and that walk reads files. A fixture keyed on a directory overrides nothing
            # the walk reads, so it would report a clean pass over a clause it never reached.
            {f"{RECORD}/mod.rs": "fn f() -> ServedHttpResponse { ServedHttpResponse::json(403, b) }\n"},
            marker="pre-exchange refusal sites are",
        ),
        Scenario(
            "the retry contract stops being derived from the machine (12d)",
            {SERVING: SERVED_STUB
                      + "fn disposition(progress: &ExchangeProgress) -> ExecutionDisposition {\n"
                        "    ExecutionDisposition::NothingExecuted\n}\n"},
            marker="does not read `retry_semantics()`",
        ),
    ]


def scenarios() -> list[Scenario]:
    return cause_scenarios() + record_scenarios() + lifecycle_scenarios()
