# SPDX-License-Identifier: Apache-2.0
"""The selftest's scenarios: every claim, undone, must be caught."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from _authorization_provenance.config import AUTHORITY_DIR, PLANE, REPO, SERVING, STAGES, VALIDATION
from _authorization_provenance.dispatch import check_dispatch, check_validation
from _authorization_provenance.rusttext import without_comments
from _authorization_provenance.serving import check_serving
from _authorization_provenance.sources import read


@dataclass(frozen=True)
class AuthorityCase:
    """Edit one authority file's source with `edit`; exactly `expected` problems must follow."""

    name: str
    file: str
    edit: Callable[[str], str]
    expected: int = 1

    def apply(self, sources: dict[str, str]) -> dict[str, str]:
        path = f"{AUTHORITY_DIR}/{self.file}"
        return {**sources, path: self.edit(sources[path])}


@dataclass(frozen=True)
class TextCase:
    """Run `check` over `text`; exactly `expected` problems must follow."""

    name: str
    check: Callable[[str], list[str]]
    text: str
    expected: int


def authority_cases() -> list[AuthorityCase]:
    return [
        # (10), the authority half: a second producer of the posture.
        AuthorityCase(
            "a second producer of the posture in the authority", "serving.rs",
            lambda t: t + "\nfn shortcut() -> AuthorizationPosture "
                          "{ AuthorizationPosture::NoPolicyConfigured }\n",
        ),
        AuthorityCase(
            "a certificate route in the authority", "request.rs",
            lambda t: t + "\nfn back_door(l: &[u8]) { let _ = extract_identity(l); }\n",
        ),
        AuthorityCase(
            "a transport hint in the authority", "verified_action.rs",
            lambda t: t.replace("let Ok(body) =", "let _ = MCP_NAME_HEADER; let Ok(body) ="),
        ),
        AuthorityCase(
            "the digest pairing deleted", "verified_action.rs",
            lambda t: t.replace("!verified.covers_body(body)", "false"),
        ),
        AuthorityCase(
            "a header parameter widened into `authorize`", "decide.rs",
            lambda t: t.replace("    body: &[u8],", "    body: &[u8],\n    headers: &[(String, String)],"),
        ),
        AuthorityCase(
            "the Mode-1 linkage form made selectable as evidence", "pdp/evidence.rs",
            lambda t: t.replace("&& b.binding_type() == BindingType::OpaqueDigest", ""),
        ),
        AuthorityCase(
            "the decision digest check deleted", "pdp/evidence.rs",
            lambda t: t.replace("match verify_pdp_decision_binding(binding, document) {",
                                "match Ok::<(), PdpBindingRefusal>(()) {"),
        ),
        AuthorityCase(
            "a sealed representation made public", "verified_actor.rs",
            lambda t: t.replace("    identity: ActorIdentity,", "    pub identity: ActorIdentity,"),
        ),
    ]


def _dispatch_with(sources: dict[str, str], **replaced: str) -> list[str]:
    """`check_dispatch` over the live inputs, except the ones a case replaces by keyword
    (`stages`, `authority`, `plane`)."""
    parts = {
        "stages": read(REPO, STAGES),
        "authority": without_comments("\n".join(sources.values())),
        "plane": read(REPO, PLANE),
    }
    parts.update(replaced)
    return check_dispatch(parts["stages"], parts["authority"], read(REPO, SERVING), parts["plane"])


def _serving_cases() -> list[TextCase]:
    # Deleting the call breaks TWO links at once and is reported as two: the region
    # assembly no longer asks, and the path no longer names the stage twice (its
    # definition and its one call site). Collapsing that to one report would hide which
    # of the two the next reader has to restore.
    return [
        TextCase("the serving stage removed", check_serving,
                 read(REPO, SERVING).replace(
                     ".authorization_stage(ex, &envelope, &decided_over)", ".no_decision()"), 2),
        # The region assembly is a link of its own: an assembly that stopped entering the
        # pre-admission region would dispatch without ever reaching the decision.
        TextCase("the pre-admission region no longer ordered", check_serving,
                 read(REPO, SERVING).replace(
                     ".admit_request(&mut ex, req.peer.as_ref(), &mut progress)", ".no_region()"), 1),
    ]


def _dispatch_cases(sources: dict[str, str]) -> list[TextCase]:
    live = without_comments("\n".join(sources.values()))
    return [
        TextCase("a second producer of the dispatchable body",
                 lambda t: _dispatch_with(sources, authority=t),
                 live + "\n    fn release(self, b: Vec<u8>) -> AuthorizedRequestBody { todo!() }\n", 1),
        TextCase("the transmitting seam widened back to `Vec<u8>`",
                 lambda t: _dispatch_with(sources, plane=t),
                 read(REPO, PLANE).replace("forwarded: AuthorizedRequestBody,", "forwarded: Vec<u8>,"), 1),
        TextCase("the ready state assembled from something other than the capability",
                 lambda t: _dispatch_with(sources, stages=t),
                 read(REPO, STAGES).replace("prepared: PreparedInnerDispatch<'a>,", "prepared: Vec<u8>,"), 1),
    ]


def text_cases(sources: dict[str, str]) -> list[TextCase]:
    """The serving, machine and validation claims, undone against their own text."""
    serving, dispatch = _serving_cases(), _dispatch_cases(sources)
    return [
        serving[0],
        serving[1],
        dispatch[0],
        dispatch[1],
        dispatch[2],
        TextCase("the reference-profile refusal removed", check_validation,
                 read(REPO, VALIDATION).replace("AuthzKind::Reference", "AuthzKind::Off"), 1),
        # (10), the serving half. The bypass this refuses is the one no type can catch:
        # a body released under a synthesized `NoPolicyConfigured` is byte-for-byte the
        # body a real decision would have released.
        TextCase("the serving path synthesizing the posture that claims nothing", check_serving,
                 read(REPO, SERVING) + "\nfn back_door() -> AuthorizedRequestBody { "
                 "AuthorizationPosture::NoPolicyConfigured.release(Vec::new()) }\n", 1),
    ]
