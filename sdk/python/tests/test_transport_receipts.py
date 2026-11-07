# SPDX-License-Identifier: Apache-2.0
"""Offline unit tests for the core's verdict as the transport adapter reports it: a
rejection receipt's binding fact, and a verified reply that is not a JSON-RPC response.
"""
import pytest

pytest.importorskip("mcp", reason="the transport adapter needs the upstream MCP SDK")

from mcp.types import JSONRPCError  # noqa: E402
from mcp_re_sdk import HttpReply  # noqa: E402
from transport_fixtures import make_config, make_request, send_one  # noqa: E402


# --- the core's verdict, stubbed at ONE shape -------------------------------------
#
# Four controls below stub `_core.verify_response`, and the seam is the right one: the
# property under test is what the ADAPTER does with a verdict, and against a recorded
# receipt a control cannot distinguish reading `verified.bound` from hard-coding `True`.
#
# What a duck-typed stub cannot do on its own is track the core's SHAPE. Four separately
# written stub classes would let the core rename a member — `execution_status`, say — and
# leave every one of them green while the adapter read `None` in production. So the shape
# is declared once, here, and `test_the_stubbed_verdict_shape_is_the_cores_own` checks it
# against `_core.PyVerifyResult` itself. That check is what makes these stubs evidence
# rather than four copies of an assumption (#746).

#: Every member the adapter reads off a verified response, with the value a verdict that
#: states nothing would carry. A stub overrides what its own control is about.
_VERDICT_MEMBERS = {
    "outcome": "success",
    "wire_code": None,
    "bound": True,
    "request_state": None,
    "execution_status": None,
    "retry_safety": None,
    "continuation_status": None,
    "retention_status": None,
}


def _stub_verdict(**over):
    """A stand-in for one `_core.verify_response` result, at the shape declared above."""
    unknown = set(over) - set(_VERDICT_MEMBERS)
    assert not unknown, f"not members of a verified response: {sorted(unknown)}"
    return type("_StubVerdict", (), {**_VERDICT_MEMBERS, **over})()


def test_the_stubbed_verdict_shape_is_the_cores_own():
    """The stubs' members are the CORE's members, checked against the core's own type.

    This is the anti-vacuity control for the four stubbed ones. R9-C094 was a fake whose
    behaviour production could not have; a duck-typed stub of an internal seam is the same
    hazard one level over — it keeps passing after the thing it stands for has moved.
    """
    import mcp_re_sdk.transport as t

    real = {name for name in dir(t._core.PyVerifyResult) if not name.startswith("_")}
    missing = sorted(set(_VERDICT_MEMBERS) - real)
    assert not missing, (
        f"the stubs declare {missing}, which PyVerifyResult does not expose — the adapter "
        f"would read nothing there in production while these controls stayed green"
    )


# --- the rejection receipt's binding fact ----------------------------------------
#
# `test_a_verified_rejection_receipt_is_delivered_as_an_error_not_a_result` in
# test_transport_replay.py pins the BOUND value against a recorded receipt. It cannot
# distinguish reading `verified.bound` from hard-coding `True`, and the unbound case is
# the security-relevant one, so it is pinned here against a stubbed verdict. The
# TypeScript twin pins the same pair.


@pytest.mark.anyio
async def test_an_unbound_rejection_receipt_is_reported_as_not_request_bound(monkeypatch):
    """A preflight-unbound receipt carries no binding to this request's evidence.

    The core verifies a rejection receipt request-bound first and preflight-unbound
    second, and says which one succeeded. An unbound receipt is genuine evidence from a
    trusted issuer, but it answers no particular transmission — one of them is an answer
    to every request from every client of that issuer for the credential's validity
    window — so an application must be able to tell "the boundary rejected MY request"
    from "a generic rejection arrived" (RSP-7). It is still an error and never a result.
    """
    import mcp_re_sdk.transport as t

    # A preflight refusal that never reached dispatch states no disposition, so every
    # execution member keeps the shared shape's `None`: the transport must emit no member
    # for it rather than inventing one.
    unbound = _stub_verdict(
        outcome="rejection", wire_code="mcp-re.authorization_binding_missing", bound=False
    )
    monkeypatch.setattr(t._core, "verify_response", lambda *a, **k: unbound)

    async def rejecting(method, target_uri, headers, body):
        return HttpReply(status=409, headers=[], body=b"{}")

    out = await send_one(make_config(), rejecting, make_request())

    error = out[0].message.error
    assert error.message == "mcp-re.authorization_binding_missing", (
        "the frozen token is what the peer said and must not be rewritten"
    )
    assert error.data == {"requestBound": False}


@pytest.mark.anyio
@pytest.mark.parametrize("absent", [None, ""])
async def test_a_wire_code_the_receipt_did_not_carry_is_not_invented(monkeypatch, absent):
    """A verified rejection receipt that carries no wire code is still a verified refusal.

    Its signature verified, so delivering it as `mcp-re.response_sig_invalid` would name a
    signature failure that did not happen, in a token the peer never sent — and an
    application branching on that token would read a provable server refusal as a local
    verification fault. Passing the absence through would deliver an empty `message`. The
    condition is the SDK's own, so it is delivered under the `mcp-re-sdk:` prefix and no
    `mcp-re.*` token is invented for it.
    """
    import mcp_re_sdk.transport as t

    silent = _stub_verdict(outcome="rejection", wire_code=absent, bound=False)
    monkeypatch.setattr(t._core, "verify_response", lambda *a, **k: silent)

    async def rejecting(method, target_uri, headers, body):
        return HttpReply(status=409, headers=[], body=b"{}")

    out = await send_one(make_config(), rejecting, make_request())

    error = out[0].message.error
    assert error.message == "mcp-re-sdk: verified rejection carried no wire code", (
        f"a {absent!r} wire code reached the application as {error.message!r}"
    )
    assert error.data == {"requestBound": False}


@pytest.mark.anyio
async def test_a_post_dispatch_rejection_reports_its_execution_and_retry_contract(monkeypatch):
    """ADR-MCPRE-058 §10 (SL-10): the disposition must reach the application.

    The server derives `execution_status` / `retry_safety` from its exchange machine and
    signs them into every rejection at or after dispatch, precisely so a client can tell
    a retry-safe failure from one whose side effect a retry performs twice. Nothing on
    the client side read them: the application saw a bare wire code and a retry-friendly
    status, retried, and the tool call ran again with a fresh nonce that passes replay
    admission. Byte-parity fixtures cannot see this — it is behaviour.
    """
    import mcp_re_sdk.transport as t

    post_dispatch = _stub_verdict(
        outcome="rejection",
        wire_code="mcp-re.inner_dispatch_indeterminate",
        execution_status="possibly_executed",
        retry_safety="unsafe_without_reconciliation",
        continuation_status="consumed",
    )
    monkeypatch.setattr(t._core, "verify_response", lambda *a, **k: post_dispatch)

    async def rejecting(method, target_uri, headers, body):
        return HttpReply(status=503, headers=[], body=b"{}")

    out = await send_one(make_config(), rejecting, make_request())

    error = out[0].message.error
    assert error.message == "mcp-re.inner_dispatch_indeterminate"
    assert error.data == {
        "requestBound": True,
        "executionStatus": "possibly_executed",
        "retrySafety": "unsafe_without_reconciliation",
        "continuationStatus": "consumed",
    }, "a member the receipt did not carry must not be invented"


# --- a verified reply that is not a JSON-RPC response ------------------------------


@pytest.mark.anyio
async def test_a_verified_reply_carrying_a_method_is_refused_not_dispatched(monkeypatch):
    """A signed reply must never become a server->client REQUEST.

    `jsonrpc_message_adapter` is a union that accepts a JSONRPCRequest, and the pydantic
    models ignore extras, so a body carrying BOTH a legal `result` and a top-level
    `method` parsed as a request and was injected into `ClientSession` as a
    server-initiated one — running the application's sampling / elicitation / roots
    handlers on attacker-chosen params. The `call_tool` that was actually made then hung
    forever, because its id had been consumed as an inbound request id.

    The Rust ambassador refuses the same body (`plain_response_from_verified`); this is
    the SDK side of that property, and the TypeScript twin pins it too.
    """
    import mcp_re_sdk.transport as t

    monkeypatch.setattr(t._core, "verify_response", lambda *a, **k: _stub_verdict())

    hostile = (
        b'{"jsonrpc":"2.0","id":1,"result":{"ok":true},'
        b'"method":"sampling/createMessage","params":{"x":1}}'
    )

    async def spliced(method, target_uri, headers, body):
        return HttpReply(status=200, headers=[], body=hostile)

    out = await send_one(make_config(), spliced, make_request())

    delivered = out[0].message
    assert isinstance(delivered, JSONRPCError), (
        f"a method-bearing body must not reach the session as {type(delivered).__name__}"
    )
    assert delivered.error.message == "mcp-re.malformed_envelope"

    # And an ordinary reply still round-trips, so the guard refuses a shape rather than
    # the success path.
    async def ordinary(method, target_uri, headers, body):
        return HttpReply(
            status=200, headers=[], body=b'{"jsonrpc":"2.0","id":9,"result":{"ok":true}}'
        )

    out = await send_one(make_config(), ordinary, make_request())
    assert out[0].message.result == {"ok": True}


@pytest.mark.anyio
async def test_a_verified_reply_with_neither_result_nor_error_is_refused(monkeypatch):
    """A signed envelope carrying no answer is not an answer.

    Handing it to the union adapter produced whichever arm happened to match, and an
    empty `{"jsonrpc":"2.0","id":1}` has no reading under which the call completed.
    """
    import mcp_re_sdk.transport as t

    monkeypatch.setattr(t._core, "verify_response", lambda *a, **k: _stub_verdict())

    for body in (
        b'{"jsonrpc":"2.0","id":1}',
        b'{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x"}}',
        b'[{"jsonrpc":"2.0","id":1,"result":{}}]',
        b'"ok"',
    ):
        async def poster(method, target_uri, headers, body=body):
            return HttpReply(status=200, headers=[], body=body)

        out = await send_one(make_config(), poster, make_request())
        delivered = out[0].message
        assert isinstance(delivered, JSONRPCError), f"{body!r} must not be delivered"
        assert delivered.error.message == "mcp-re.malformed_envelope"
