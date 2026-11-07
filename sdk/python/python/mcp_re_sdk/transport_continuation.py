# SPDX-License-Identifier: Apache-2.0
"""Driving a multi-round-trip call: the answer leg an ADR-MCPS-047 elicitation earns.

An elicitation pauses a call rather than finishing it. The application's
``answer_input_required`` handler supplies the answers; this module turns that answer
into the next leg's parameters, or refuses the call closed
(:class:`~mcp_re_sdk.transport_errors.ContinuationNotAnswered`) when no answer leg can be
driven.
"""
from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Mapping, Optional, Union

from .correlation import ContinuationHandles
from .transport_errors import ContinuationNotAnswered

if TYPE_CHECKING:
    from .transport_config import McpReConfig


@dataclass(frozen=True)
class InputRequired:
    """A verified ADR-MCPS-047 elicitation, and everything answering it needs.

    Everything here was read from the VERIFIED response — the signature, content digest
    and request binding all checked out before this was built.
    """

    #: The two evidence handles + opaque state the answer leg signs over.
    handles: ContinuationHandles
    #: The MCP method being continued, unchanged across the chain.
    method: str
    #: The params of the leg that earned this elicitation.
    params: Mapping[str, Any]
    #: The verified `InputRequiredResult` — `requestState` plus whatever the server used
    #: to describe what it wants (`elicitation` / `inputRequests`). Passed through
    #: uninterpreted: what to ask, and how, is the application's decision.
    result: Mapping[str, Any]
    #: Which continuation round this is, counting from 1.
    round: int


#: What an ``answer_input_required`` handler returns: the `inputResponses` to continue
#: with, or ``None`` to decline. May be a coroutine — eliciting from a human is I/O.
InputAnswer = Union[Optional[Mapping[str, Any]], Awaitable[Optional[Mapping[str, Any]]]]


def _verified_result(body: bytes) -> Mapping[str, Any]:
    """The `result` object of a verified reply, for an answer-leg handler to read."""
    result = json.loads(body).get("result")
    return result if isinstance(result, dict) else {}


def _answer_leg_id(request_id, round_index: int) -> str:
    """The JSON-RPC id for an answer leg.

    SEP-2322 makes the retry an INDEPENDENT request with a new id, so the chain must not
    re-use the one the session issued. Derived from it rather than drawn at random, so a
    capture or log shows which call the leg belongs to.
    """
    return f"{request_id}/mrt-{round_index}"


def _check_answerable(config: McpReConfig, elicitation: InputRequired) -> None:
    """Raise unless an answer leg can still be driven for this round.

    Checked BEFORE the handler runs: a call that has already used up its continuation
    budget must not prompt for an answer it cannot send.
    """
    method = elicitation.method
    if elicitation.round > config.max_continuation_rounds:
        raise ContinuationNotAnswered(
            f"'{method}' elicited {elicitation.round} times, past the "
            f"max_continuation_rounds ceiling of {config.max_continuation_rounds}"
        )
    if config.answer_input_required is None:
        raise ContinuationNotAnswered(
            f"'{method}' returned an ADR-MCPS-047 elicitation and no "
            f"answer_input_required handler is installed, so no answer leg can "
            f"be signed"
        )


def _check_answer(method: str, responses: Any) -> Mapping[str, Any]:
    """The handler's answer if it is a JSON object, or raise."""
    if responses is None:
        raise ContinuationNotAnswered(
            f"the elicitation from '{method}' was declined by "
            f"answer_input_required"
        )
    if not isinstance(responses, Mapping):
        raise ContinuationNotAnswered(
            f"answer_input_required returned {type(responses).__name__}; the "
            f"MRTR answer leg carries `inputResponses` as a JSON object"
        )
    return responses


async def _elicited_answers(
    config: McpReConfig, elicitation: InputRequired
) -> Mapping[str, Any]:
    """The `inputResponses` the application gave for this round's elicitation, or raise."""
    _check_answerable(config, elicitation)
    responses = config.answer_input_required(elicitation)
    if inspect.isawaitable(responses):
        responses = await responses
    return _check_answer(elicitation.method, responses)


def _answer_leg_params(
    elicitation: InputRequired, responses: Mapping[str, Any]
) -> dict:
    """The next leg's params: the same call, carrying the answers and echoing the opaque
    state back, bound to the handles of the exchange that asked for them."""
    return {
        **elicitation.params,
        "inputResponses": dict(responses),
        "requestState": elicitation.handles.request_state,
    }
