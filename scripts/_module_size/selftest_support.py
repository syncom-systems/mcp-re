# SPDX-License-Identifier: Apache-2.0
"""Shared pieces of the gate's selftest: the failure signal and the probe crate."""

from __future__ import annotations

from pathlib import Path

from _module_size.config import THRESHOLD
from _module_size.measure import check

REL_BIG = "mcp-re-probe/src/big.rs"


class SelftestFailure(Exception):
    """An assertion of the selftest did not hold; the message is the report."""


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise SelftestFailure(message)


def lines(count: int) -> str:
    """A Rust source of `count` one-line functions."""
    return "\n".join(f"fn f{i}() {{}}" for i in range(count)) + "\n"


def entry_for(status: str, baseline: int, **extra) -> dict[str, dict]:
    """A one-entry register for the probe file."""
    return {REL_BIG: {"path": REL_BIG, "baseline_prod_loc": baseline,
                      "baseline_sha": "0" * 7, "status": status, **extra}}


class Probe:
    """A scratch crate holding one oversized file the selftest mutates in place."""

    def __init__(self, root: Path) -> None:
        self.root = root
        crate = root / "mcp-re-probe" / "src"
        crate.mkdir(parents=True)
        self.big = crate / "big.rs"
        self.big.write_text(lines(THRESHOLD + 5))
        (crate / "small.rs").write_text("fn s() {}\n")

    def problems(self, registry: dict[str, dict]) -> list[str]:
        return check(self.root, registry)[0]

    def set_lines(self, count: int) -> None:
        self.big.write_text(lines(count))

    def append(self, text: str) -> None:
        self.big.write_text(self.big.read_text() + text)
