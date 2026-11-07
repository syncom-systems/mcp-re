# SPDX-License-Identifier: Apache-2.0
"""The one way a stage of the gate stops the run."""

from __future__ import annotations


class Failure(Exception):
    """A refusal, carried as the lines the gate prints to stderr before it exits 1."""

    def __init__(self, *lines: str) -> None:
        super().__init__(lines[0] if lines else "")
        self.lines = lines
