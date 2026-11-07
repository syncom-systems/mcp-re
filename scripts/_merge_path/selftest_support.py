# SPDX-License-Identifier: Apache-2.0
"""What the selftest groups share: a failure that carries its message."""

from __future__ import annotations


class SelftestFailure(Exception):
    """A selftest assertion that did not hold; the message is printed after `SELFTEST FAIL:`."""


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise SelftestFailure(message)
