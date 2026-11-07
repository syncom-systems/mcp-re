# SPDX-License-Identifier: Apache-2.0
"""Parsing Signature-Input and Signature members, and rebuilding the RFC 9421 signature base."""

from __future__ import annotations

import base64

from _rfc9421_cross.messages import component_value, header


def parse_signature_input(member: str) -> tuple[list[tuple[str, bool]], str]:
    """Return the ordered [(identifier, is_req)] list and the literal params
    string (everything after the closing paren, used verbatim in the base)."""
    member = member.strip()
    assert member.startswith("("), "inner list must start with ("
    close = member.index(")")
    comps: list[tuple[str, bool]] = []
    for item in member[1:close].split():
        is_req = item.endswith(";req")
        if is_req:
            item = item[: -len(";req")]
        assert item.startswith('"') and item.endswith('"'), f"bad identifier {item}"
        comps.append((item[1:-1], is_req))
    return comps, member[close + 1 :]


def _unquoted_commas(value: str):
    in_quotes = False
    for i, c in enumerate(value):
        in_quotes ^= c == '"'
        if c == "," and not in_quotes:
            yield i


def _split_members(value: str) -> list[str]:
    members, start = [], 0
    for i in _unquoted_commas(value):
        members.append(value[start:i])
        start = i + 1
    members.append(value[start:])
    return members


def dictionary_member(value: str, label: str) -> str:
    """Extract `label=...` from a Structured-Fields dictionary, honoring quotes."""
    for m in (m.strip() for m in _split_members(value)):
        if m.startswith(label + "="):
            return m[len(label) + 1 :].strip()
    raise ValueError(f"label {label} not found")


def reconstruct_base(comps, sig_params_value, request, response) -> bytes:
    """`sig_params_value` is the FULL `Signature-Input` member value
    (`("a" "b");created=...`), used verbatim as the @signature-params line."""
    lines = []
    for ident, is_req in comps:
        suffix = ";req" if is_req else ""
        lines.append(f'"{ident}"{suffix}: {component_value(ident, is_req, request, response)}')
    lines.append(f'"@signature-params": {sig_params_value}')
    return "\n".join(lines).encode()


def signature_bytes(headers, label) -> bytes:
    sig_member = dictionary_member(header(headers, "signature"), label)
    assert sig_member.startswith(":") and sig_member.endswith(":"), "byte-sequence form"
    return base64.b64decode(sig_member[1:-1])


def keyid_and_tag(params: str) -> tuple[str, str]:
    keyid = tag = None
    for p in params.split(";"):
        p = p.strip()
        if p.startswith('keyid="'):
            keyid = p[len('keyid="') : -1]
        elif p.startswith('tag="'):
            tag = p[len('tag="') : -1]
    return keyid, tag
