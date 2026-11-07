# SPDX-License-Identifier: Apache-2.0
"""Offline unit tests for what the transport adapter signs and what it is configured
with: the freshness inputs, the transmitted bytes, the authorization binding digest, the
delegated-verification anchor and the revocation denylist.
"""
import json

import anyio
import pytest

pytest.importorskip("mcp", reason="the transport adapter needs the upstream MCP SDK")

from mcp.shared.message import SessionMessage  # noqa: E402
from mcp_re_sdk import (  # noqa: E402
    AuthzSystemReferenceProvider,
    CorrelationStore,
    HttpReply,
    mcp_re_http_transport,
    McpReError,
    McpReSdkError,
    OpaqueBytesProvider,
)
from mcp_re_sdk.transport_binding import _authz_binding_digest, _bindings_json  # noqa: E402
from transport_fixtures import capturing_poster, make_config, make_request, send_one  # noqa: E402


# --- signing inputs --------------------------------------------------------------


@pytest.mark.anyio
async def test_freshness_is_generated_here_so_a_caller_cannot_repeat_a_nonce():
    # A nonce that repeats inside the window is a defect, not a policy knob.
    calls = []
    poster = capturing_poster(calls)
    for _ in range(2):
        await send_one(make_config(), poster, make_request())

    sigs = [
        next(v for k, v in c["headers"] if k.lower() == "signature") for c in calls
    ]
    assert sigs[0] != sigs[1]


@pytest.mark.anyio
async def test_an_injected_clock_and_ttl_are_honoured():
    calls = []
    config = make_config(clock=lambda: 1_000, request_ttl=30, route="a")
    await send_one(config, capturing_poster(calls), make_request())
    sig_input = next(v for k, v in calls[0]["headers"] if k.lower() == "signature-input")
    assert "created=1000" in sig_input
    assert "expires=1030" in sig_input


@pytest.mark.anyio
async def test_the_signed_body_is_the_request_the_caller_described():
    calls = []
    await send_one(make_config(), capturing_poster(calls), make_request(method="tools/list", id=7))
    body = json.loads(calls[0]["body"])
    assert body["method"] == "tools/list"
    assert body["id"] == 7


@pytest.mark.anyio
async def test_the_verifier_is_shown_the_bytes_that_were_transmitted(monkeypatch):
    """The verdict is about the transmission, not about a body that resembles it.

    `test_the_signed_body_is_the_request_the_caller_described` reads the posted body as
    JSON, so it cannot tell `signed.body()` from a re-serialization of it: both decode to
    the same document, and an implementation that re-derived the bytes for either leg
    would keep it green. What the exchange must establish is BYTE identity — the value
    `sign_request` produced is the one that went on the wire and the one the verifier
    judged — because the signature covers bytes, and a verdict computed over anything
    else answers a question nobody asked.
    """
    import mcp_re_sdk.transport as t

    seen: dict = {}

    async def poster(method, target_uri, headers, body) -> HttpReply:
        seen["posted"] = body
        return HttpReply(status=200, headers=[], body=b"{}")

    def capturing_verify(*args, **kwargs):
        seen["verified"] = args[6]
        raise McpReError("mcp-re.replay_detected")

    monkeypatch.setattr(t._core, "verify_response", capturing_verify)
    await send_one(make_config(), poster, make_request(method="tools/list", id=7))

    assert seen["posted"] == seen["verified"], (
        "the verifier judged bytes other than the ones transmitted"
    )
    assert json.loads(seen["posted"])["method"] == "tools/list"


@pytest.mark.anyio
async def test_the_correlation_entry_records_the_authorization_binding_digest():
    # ADR-MCPS-044 enumerates it; retained for audit only, never re-interpreted.
    #
    # The expected value is a LITERAL, not a recomputation. Recomputing it with the
    # SDK's own serializer is what let Python and TypeScript drift: `json.dumps`
    # defaults to `", "`/`": "` separators and `JSON.stringify` emits none, so identical
    # bindings produced different digests and an audit pipeline reconciling the two saw
    # a false "artifact binding changed". The TypeScript twin's test pins this SAME
    # string — that is the point of writing it down.
    store = CorrelationStore()
    config = make_config(authorization=[OpaqueBytesProvider("human-approval", b"doc")])

    async def poster(method, target_uri, headers, body) -> HttpReply:
        await anyio.sleep(5)
        raise McpReError("mcp-re.replay_detected")

    async with mcp_re_http_transport(config, poster, correlation=store) as (read, write):
        await write.send(SessionMessage(make_request()))
        await anyio.sleep(0.05)
        pending = next(iter(store))
        canonical = (
            '[{"artifact_type":"human-approval","form":"opaque-bytes",'
            '"material_b64url":"ZG9j"}]'
        )
        assert _bindings_json(config, "tools/list") == canonical, (
            "compact separators, sorted keys — byte-identical to JSON.stringify"
        )
        assert (
            pending.authz_binding_digest
            == "sha-256:huucRBvtO7V1Xm8EFbC6ci-xlsf8EYyNZQix9sJx64Q"
        )


def test_the_canonical_bindings_json_emits_raw_utf8_like_json_stringify():
    """A non-ASCII binding field must digest to the same bytes in both SDKs.

    ``json.dumps`` escapes every non-ASCII character as ``\\uXXXX`` unless told not to;
    ``JSON.stringify`` emits raw UTF-8. Since :func:`_authz_binding_digest` is taken over
    exactly this text, an ``authorization_system_id``, ``reference_scheme_id`` or
    ``reference_value`` carrying a non-ASCII character — a tenant name, a grant handle —
    otherwise digested to two different values, and an audit pipeline reconciling a
    Python client's record against a TypeScript client's read that as "the artifact
    binding changed".

    The expected string is a LITERAL, and the TypeScript twin's test pins the same one.
    """
    config = make_config(
        authorization=[
            AuthzSystemReferenceProvider(
                "pdp-decision",
                b"doc",
                authorization_system_id="pdp-sé",
                reference_scheme_id="urn:système",
                reference_value="grant-café-✓",
            )
        ]
    )
    canonical = _bindings_json(config, "tools/list")

    assert canonical == (
        '[{"artifact_type":"pdp-decision","authorization_system_id":"pdp-sé",'
        '"form":"authz-system-reference","material_b64url":"ZG9j",'
        '"reference_scheme_id":"urn:système","reference_value":"grant-café-✓"}]'
    )
    assert "\\u" not in canonical, "an escaped non-ASCII character is not JSON.stringify"
    assert _authz_binding_digest(canonical) == "sha-256:5qndaYSZ4RWRPC68gVX125zTyK8XeWHdwWvnFZnr0XI"


@pytest.mark.anyio
async def test_a_request_with_no_bindings_records_no_digest():
    store = CorrelationStore()

    async def poster(method, target_uri, headers, body) -> HttpReply:
        await anyio.sleep(5)
        raise McpReError("mcp-re.replay_detected")

    async with mcp_re_http_transport(make_config(), poster, correlation=store) as (read, write):
        await write.send(SessionMessage(make_request()))
        await anyio.sleep(0.05)
        assert next(iter(store)).authz_binding_digest is None


# --- the delegated-verification anchor -------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "issuer_key_id",
        "issuer_pubkey_b64url",
        "issuer_trust_domain",
        "issuer_subject",
        "expected_audience_hash",
        "verifier_audiences",
        "accepted_epochs",
    ],
)
def test_an_incomplete_trust_anchor_fails_at_construction(field):
    """Empty is not a relaxed check — it is a check nothing can satisfy.

    An empty `accepted_epochs` rejects every response as a stale trust epoch, an empty
    `verifier_audiences` as an audience mismatch. The client is unusable rather than
    unsafe, but it should not have to send a request to find that out. TypeScript makes
    these required interface fields; this is Python stating the same requirement.
    """
    empty = [] if field in ("verifier_audiences", "accepted_epochs") else ""
    with pytest.raises(McpReSdkError) as ei:
        make_config(**{field: empty})
    assert field in str(ei.value)
    assert "trust anchor is incomplete" in str(ei.value)


# --- the revocation denylist -----------------------------------------------------
#
# `revoked_identifiers` is the one config field whose wrong value fails OPEN. Every
# sibling anchor field degrades into "nothing verifies"; a malformed denylist degrades
# into "nothing is revoked" while still reporting a denylist as configured. Mirrors
# `McpReHttpTransport revocation denylist shape` in the TypeScript suite.


def test_a_bare_string_denylist_is_refused_rather_than_expanded_per_character():
    """``list("kid-compromised")`` is a NON-EMPTY list of single characters.

    None of them can match a `delegated_kid`, `issuer_kid` or credential `jti`, so the
    compromised key stays accepted for its whole TTL and epoch window while the operator
    believes revocation is in force. No type checker objects, because a `str` IS a
    `Sequence[str]`.
    """
    with pytest.raises(McpReSdkError, match="must be a sequence of identifier strings"):
        make_config(revoked_identifiers="kid-compromised")


@pytest.mark.parametrize("bad", [["kid-1", ""], [7], [None]])
def test_a_denylist_entry_that_cannot_match_an_identifier_is_refused(bad):
    with pytest.raises(McpReSdkError, match="non-empty strings"):
        make_config(revoked_identifiers=bad)


def test_a_well_formed_denylist_and_the_empty_ttl_only_posture_are_accepted():
    assert make_config(revoked_identifiers=["kid-1"]).revoked_identifiers == ["kid-1"]
    assert make_config(revoked_identifiers=[]).revoked_identifiers == []
    assert make_config().revoked_identifiers == ()
