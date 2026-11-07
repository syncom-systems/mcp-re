# SPDX-License-Identifier: Apache-2.0
"""The values a placeholder may take: restricted characters, CIDR networks, single-host source lists."""

from __future__ import annotations

import ipaddress
import re

VALUE = re.compile(r"[A-Za-z0-9:][A-Za-z0-9.:/_+=-]*")
CIDRS_VALUE = re.compile(r"[0-9A-Fa-f.:]+/[0-9]{1,3}(,[0-9A-Fa-f.:]+/[0-9]{1,3})*")
MAX_SOURCES = 8


class Refused(ValueError):
    pass


def _check_single_host(name: str, source: str) -> None:
    try:
        network = ipaddress.ip_network(source, strict=True)
    except ValueError as exc:
        raise Refused(f"{name}: {source!r} is not a network in CIDR form: {exc}") from exc
    if network.prefixlen != network.max_prefixlen:
        raise Refused(f"{name}: {source!r} is a range, not one approved source address "
                      f"(/{network.max_prefixlen})")


def check_sources(name: str, value: str) -> list[str]:
    """The addresses of a `*_CIDRS` value: each a strict single-host network."""
    if not CIDRS_VALUE.fullmatch(value):
        raise Refused(f"{name}={value!r}: a source list is comma-separated addresses in CIDR form")
    sources = value.split(",")
    if len(sources) > MAX_SOURCES or len(set(sources)) != len(sources):
        raise Refused(f"{name}={value!r}: at most {MAX_SOURCES} distinct source addresses")
    for source in sources:
        _check_single_host(name, source)
    return sources


def _check_network(name: str, value: str) -> None:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise Refused(f"{name}={value!r} is not a network in CIDR form: {exc}") from exc
    if network.prefixlen == 0:
        raise Refused(f"{name}={value!r} opens the resource to the whole internet")


def check_value(name: str, value: str) -> None:
    if name.endswith("_CIDRS"):
        check_sources(name, value)
        return
    if not VALUE.fullmatch(value):
        raise Refused(f"{name}={value!r}: values are restricted to {VALUE.pattern}")
    if name.endswith("_CIDR"):
        _check_network(name, value)
