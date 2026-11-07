# SPDX-License-Identifier: Apache-2.0
"""Resolving one covered component from a fixture's request or response, RFC 9421-style."""

from __future__ import annotations


def header(headers: list[list[str]], name: str) -> str | None:
    """Exact-once, case-insensitive header lookup; None if absent."""
    found = None
    for k, v in headers:
        if k.lower() == name.lower():
            if found is not None:
                raise ValueError(f"duplicate header {name}")
            found = v.strip()
    return found


def authority_of(target_uri: str) -> str:
    rest = target_uri.split("://", 1)[1]
    end = min([i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i >= 0] + [len(rest)])
    return rest[:end].lower()


def path_of(target_uri: str) -> str:
    rest = target_uri.split("://", 1)[1]
    idx = [i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i >= 0]
    if not idx:
        return "/"
    start = min(idx)
    if rest[start] != "/":
        return "/"
    tail = rest[start:]
    end = min([i for i in (tail.find("?"), tail.find("#")) if i >= 0] + [len(tail)])
    return tail[:end]


DERIVED_COMPONENTS = {
    "method": lambda msg: msg["method"].upper(),
    "target-uri": lambda msg: msg["target_uri"],
    "authority": lambda msg: authority_of(msg["target_uri"]),
    "path": lambda msg: path_of(msg["target_uri"]),
    "status": lambda msg: str(msg["status"]),
}


def _derived_value(ident: str, msg: dict) -> str:
    derive = DERIVED_COMPONENTS.get(ident[1:])
    if derive is None:
        raise ValueError(f"unsupported derived component {ident}")
    return derive(msg)


def component_value(ident: str, req_bool: bool, request: dict | None, response: dict | None) -> str:
    """Resolve one covered component, RFC 9421-style. `;req` resolves against
    the request; otherwise against the response (if any) or the request."""
    msg = request if (req_bool or response is None) else response
    if msg is None:
        raise ValueError(f"no source message for {ident}")
    if ident.startswith("@"):
        return _derived_value(ident, msg)
    val = header(msg["headers"], ident)
    if val is None:
        raise ValueError(f"missing covered field {ident}")
    return val
