# SPDX-License-Identifier: Apache-2.0
"""Configuration for the MCP-RE transport adapter, and the poster contract it runs over.

Everything in :class:`McpReConfig` is validated where it first enters SDK-owned code, so
a value that would deadlock the session, fail open, or reject every response is refused
at construction, naming what is wrong.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, Optional, Sequence

from . import _core
from .authorization import AuthorizationBindingPolicy, AuthorizationBindingProvider
from .correlation import ContinuationHandles
from .custody import McpReSdkError, Signer, SignerPolicy
from .transport_continuation import InputAnswer, InputRequired
from .transport_freshness import _default_clock, _default_nonce


#: Widest delegation clock skew a caller may configure, in seconds: the native core's own
#: bound, read from it, so one deployment does not run two different notions of "close
#: enough" — beyond it the credential's nbf/exp window stops bounding anything.
MAX_CLOCK_SKEW_BOUND = _core.max_clock_skew_bound()


@dataclass(frozen=True)
class HttpReply:
    """What a ``poster`` returns: the raw HTTP response, unparsed and unverified."""

    status: int
    headers: list
    body: bytes


#: Send one signed POST. ``(method, target_uri, headers, body) -> HttpReply``.
Poster = Callable[[str, str, list, bytes], Awaitable[HttpReply]]


def _is_plain_int(value: object) -> bool:
    """An ``int`` that is not a ``bool``, which Python would otherwise count as one."""
    return isinstance(value, int) and not isinstance(value, bool)


def _check_concurrency_bound(n: object) -> None:
    # A bound of 0 is not a degenerate case that merely throttles: every sender waits for
    # a slot that can never be released, so the session deadlocks in silence.
    if not _is_plain_int(n) or n < 1:
        raise McpReSdkError(
            f"max_concurrent_exchanges must be a positive integer, got {n!r}"
        )


def _check_continuation_bound(r: object) -> None:
    # Zero rounds is a meaningful setting — it refuses continuation outright — so only a
    # negative or non-integer bound is rejected here.
    if not _is_plain_int(r) or r < 0:
        raise McpReSdkError(
            f"max_continuation_rounds must be a non-negative integer, got {r!r}"
        )


def _check_clock_skew(s: object) -> None:
    # The delegation credential's nbf/exp window is only as strong as the skew allowed
    # around it: `now + skew < nbf` and `now - skew > exp` are how it is applied, so a
    # large value accepts a credential arbitrarily far outside its validity window and a
    # negative one distorts the comparison rather than tightening it. Nothing downstream
    # bounds this — DelegationPolicy stores it verbatim — so it is checked where it
    # enters SDK-owned code, mirroring the RFC 9421 skew, which is capped at 300s by
    # VerifierPolicy.
    if not _is_plain_int(s) or not 0 <= s <= MAX_CLOCK_SKEW_BOUND:
        raise McpReSdkError(
            f"max_clock_skew must be an integer in 0..={MAX_CLOCK_SKEW_BOUND} "
            f"seconds, got {s!r}"
        )


def _check_revocation_denylist(identifiers: Sequence[str]) -> None:
    # Checked for SHAPE because this is the one field whose wrong value fails OPEN. A
    # single identifier written as a bare string satisfies `Sequence[str]`, so no type
    # checker objects, and `list("kid-1")` expands it to one entry per character: the
    # denylist is non-empty, reports as configured, and matches no `delegated_kid`,
    # `issuer_kid` or `jti` that can exist. The operator believes a compromised key is
    # revoked while the client accepts it for its whole TTL and epoch window.
    if isinstance(identifiers, (str, bytes, bytearray)):
        raise McpReSdkError(
            "revoked_identifiers must be a sequence of identifier strings, not a "
            f"bare {type(identifiers).__name__}: it would be expanded "
            "one character per entry, matching no identifier and disabling "
            "revocation while reporting a denylist as configured"
        )
    bad = [v for v in identifiers if not isinstance(v, str) or not v]
    if bad:
        raise McpReSdkError(
            f"revoked_identifiers entries must be non-empty strings, got {bad!r}; "
            "an entry that cannot match an identifier silently revokes nothing"
        )


#: The string members of the delegated-verification anchor, and the sequence members.
_ANCHOR_STRINGS = (
    "issuer_key_id",
    "issuer_pubkey_b64url",
    "issuer_trust_domain",
    "issuer_subject",
    "expected_audience_hash",
)
_ANCHOR_SEQUENCES = ("verifier_audiences", "accepted_epochs")


def _check_trust_anchor(config: McpReConfig) -> None:
    # Every anchor field is compared against the credential the server presents, and an
    # empty value cannot match anything: an empty `accepted_epochs` fails every response
    # as a stale trust epoch, an empty `verifier_audiences` as an audience mismatch, an
    # empty issuer key as an invalid key. The client is therefore not *unsafe* with them
    # unset — it is unusable — but it does not discover that until the first response
    # comes back looking like a server fault. TypeScript makes these required interface
    # fields; this is where Python states the same requirement, at construction, naming
    # what is missing.
    missing = [name for name in _ANCHOR_STRINGS if not getattr(config, name)] + [
        name for name in _ANCHOR_SEQUENCES if not list(getattr(config, name))
    ]
    if missing:
        raise McpReSdkError(
            "the delegated-verification trust anchor is incomplete: "
            f"{', '.join(sorted(missing))} must be set. Every response is verified "
            "against these, so an empty value rejects every response the server "
            "sends rather than relaxing the check."
        )


@dataclass
class McpReConfig:
    """Everything the adapter needs to sign one request and verify one response.

    Freshness is generated here, not by the caller: a nonce that repeats inside the
    window is a defect, not a policy knob.
    """

    # --- signing ---
    signer: Signer
    audience_id: str
    target_uri: str
    dpop_token: str
    route: Optional[str] = None
    policy: Optional[SignerPolicy] = None

    # --- delegated verification (ADR-MCPRE-052): the trusted ROOT ISSUER anchor ---
    issuer_key_id: str = ""
    issuer_pubkey_b64url: str = ""
    issuer_role: str = "server"
    issuer_trust_domain: str = ""
    issuer_subject: str = ""
    verifier_audiences: Sequence[str] = ()
    expected_audience_hash: str = ""
    accepted_epochs: Sequence[str] = ()
    max_clock_skew: int = 60

    #: This client's static denylist of delegated key ids, issuer key ids, and credential
    #: `jti` values. Any hit fails the response closed.
    #:
    #: **Empty is the TTL-only posture, and it is the default.** With no denylist the
    #: client relies entirely on short delegated-key lifetimes and on the accepted-epoch
    #: set to retire a compromised key: a credential stays acceptable until it expires or
    #: its epoch leaves `accepted_epochs`. That is a legitimate deployment choice — it is
    #: what the audited core calls the explicit TTL-only posture — but stating it here
    #: makes it a choice rather than something that happened by omission.
    revoked_identifiers: Sequence[str] = ()

    # --- authorization bindings (bind-not-interpret) ---
    authorization: Sequence[AuthorizationBindingProvider] = ()
    authorization_policy: Optional[AuthorizationBindingPolicy] = None

    # --- freshness ---
    request_ttl: int = 300
    clock: Callable[[], int] = _default_clock
    nonce_factory: Callable[[], str] = _default_nonce

    #: How many signed exchanges may be in flight at once.
    #:
    #: MCP is not lock-step — a client may have several requests outstanding, and each
    #: MCP-RE exchange is an independent signed POST with its own nonce and its own
    #: correlation entry, so nothing about the protocol requires serializing them. Running
    #: them one at a time would make one slow tool call block every other, which is
    #: head-of-line blocking the transport has no reason to impose.
    #:
    #: It is bounded rather than unlimited because each in-flight exchange holds a
    #: connection in the caller's `poster` and a signing operation (a KMS round trip under
    #: non-exporting custody); an unbounded fan-out would let a burst of calls exhaust
    #: either. Raise it for a client that genuinely wants more parallelism.
    max_concurrent_exchanges: int = 8

    #: Called with `(method, server_keyid)` for each client->server notification whose
    #: signed 202 verified. Observability only — the acceptance claim has already been
    #: checked by the time this runs, and declining to observe it changes nothing.
    #:
    #: What a verified acknowledgement means is exactly: the enforcement boundary
    #: authenticated and accepted the message. NOT that the action completed — a verified
    #: ack for `notifications/cancelled` does not mean anything was cancelled.
    on_notification_acknowledged: Optional[Callable[[str, str], None]] = None

    #: Called with `(descriptor, error)` when an outbound message's outcome cannot be
    #: correlated to a request id, so it cannot be delivered as a JSON-RPC error. Two
    #: events reach it: a notification whose signed 202 did not verify
    #: (:class:`NotificationNotAcknowledged`, descriptor = the method), and a
    #: client->server response, which MCP-RE profiles no carrier for
    #: (:class:`ClientResponseUnsupported`, descriptor = the JSON-RPC message type).
    #:
    #: This is the only place either outcome is observable, so it is where an embedder
    #: learns that a message it emitted was NOT delivered. It belongs to the config
    #: rather than the module because a process-global sink lets one embedder's
    #: assignment swallow another transport's failures.
    #:
    #: Unset, the module-level ``mcp_re_sdk.transport.on_notification_failure`` is the
    #: process-wide fallback, and it prints to stderr.
    on_undeliverable: Optional[Callable[[str, BaseException], None]] = None

    #: Called when a verified response is an ADR-MCPS-047 `InputRequiredResult`, with the
    #: handles its answer leg must sign over. Observability only: it fires once per
    #: continuation round, and it does not decide anything. Answering is
    #: :attr:`answer_input_required`'s job.
    on_input_required: Optional[Callable[[ContinuationHandles], None]] = None

    #: Answers an elicitation, so the adapter can drive the ADR-MCPS-047 answer leg
    #: itself. Return the `inputResponses` to continue with, or ``None`` to decline.
    #: May be a coroutine.
    #:
    #: With a handler installed, a multi-round-trip tool is an ordinary ``call_tool``
    #: from the application's side: the adapter signs the answer leg over the verified
    #: handles, posts it, verifies the reply, and repeats until a terminal result — which
    #: is what the caller's await resolves to. Without one, an elicitation cannot be
    #: continued and the exchange fails closed with :class:`ContinuationNotAnswered`,
    #: because a pause delivered as a result would read as a finished call.
    answer_input_required: Optional[Callable[[InputRequired], InputAnswer]] = None

    #: How many times one call may be elicited before the adapter gives up.
    #:
    #: A continuation chain is driven by whatever the server asks for, so it is the
    #: server that decides how long it runs. Without a ceiling a hostile or looping peer
    #: could keep one ``call_tool`` in an elicitation cycle indefinitely, re-prompting a
    #: user each round. Four is well past any interactive tool's genuine need; raise it
    #: for a workflow that really does have more steps.
    max_continuation_rounds: int = 4

    def __post_init__(self) -> None:
        # Validated where the value first enters SDK-owned code.
        _check_concurrency_bound(self.max_concurrent_exchanges)
        _check_continuation_bound(self.max_continuation_rounds)
        _check_clock_skew(self.max_clock_skew)
        _check_revocation_denylist(self.revoked_identifiers)
        _check_trust_anchor(self)
