# SPDX-License-Identifier: Apache-2.0
"""The authorization bindings a request carries, serialized for the signer and for audit.

Both serializations are shared with the TypeScript SDK byte for byte; the native core
re-parses the JSON structurally, so neither text reaches the wire as written.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Optional

from .authorization import BindingRequestContext
from .transport_config import McpReConfig


def _binding_context(config: McpReConfig, method: str) -> BindingRequestContext:
    return BindingRequestContext(
        audience_id=config.audience_id,
        target_uri=config.target_uri,
        method=method,
        route=config.route,
    )


def _bindings_json(config: McpReConfig, method: str) -> Optional[str]:
    """The provider specs, serialized CANONICALLY, byte-identical to TypeScript.

    Three settings are what make it byte-identical to the TypeScript twin's
    ``bindingsJson``, and each one is a way the two serializers differ by default:

    * ``separators=(",", ":")`` — ``json.dumps`` pads with ``", "``/``": "``,
      ``JSON.stringify`` emits none;
    * ``sort_keys=True`` — key order is otherwise whatever each provider built;
    * ``ensure_ascii=False`` — ``json.dumps`` escapes every non-ASCII character as
      ``\\uXXXX``, ``JSON.stringify`` emits raw UTF-8, so an ``authorization_system_id``,
      ``reference_scheme_id`` or ``reference_value`` carrying a non-ASCII character
      (a tenant name, a grant handle) would digest to two different values.

    :func:`_authz_binding_digest` is taken over exactly this text, and SDK-1/SDK-4
    require the two languages to record the same digest for the same bindings — an audit
    pipeline reconciling a Python client's record against a TypeScript client's must not
    read a difference in serializer as "the artifact binding changed".

    The wire is unaffected either way: the native core re-parses this structurally and
    digests the decoded material, never this text.
    """
    if not config.authorization:
        return None
    ctx = _binding_context(config, method)
    return json.dumps(
        [p.spec(ctx) for p in config.authorization],
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    )


def _authz_binding_digest(bindings_json: Optional[str]) -> Optional[str]:
    """``sha-256:<b64url>`` over the canonical serialization of the binding specs.

    NOT over the signed evidence bytes: the core digests the artifact MATERIAL and this
    is a digest of the spec JSON, so the two are different values and this one cannot be
    recomputed from a captured request. It identifies WHICH artefacts a request was
    bound to, for reconciliation against another client's record of the same call —
    which is why it has to be byte-identical across SDKs (see :func:`_bindings_json`).

    ADR-MCPS-044 enumerates this among the fields a conforming client keeps per
    outstanding request. It is retained for audit only and never re-interpreted
    (bind-not-interpret): it records WHICH authorization artefacts this request was bound
    to, so an audit trail can be reconciled against the signed bytes without the
    transport ever parsing them. ``None`` when the request carried no bindings.
    """
    if bindings_json is None:
        return None
    digest = hashlib.sha256(bindings_json.encode()).digest()
    return "sha-256:" + base64.urlsafe_b64encode(digest).decode().rstrip("=")
