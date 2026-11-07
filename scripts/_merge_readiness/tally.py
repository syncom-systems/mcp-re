# SPDX-License-Identifier: Apache-2.0
"""The selftest's failure counter."""

from __future__ import annotations


class Tally:
    """Counts the selftest's failures and prints each as it happens."""

    def __init__(self) -> None:
        self.bad = 0

    def fail(self, message: str) -> None:
        print(f"  FAIL {message}")
        self.bad += 1

    def expect(self, ok: bool, message: str) -> None:
        if not ok:
            self.fail(message)
