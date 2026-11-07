"""Finding sink shared by the Python and Rust passes: where findings go, the scan
root they are reported relative to, and the allowlist that can suppress them."""

from dataclasses import dataclass
from typing import Callable

from _prescan_allow import Allowlist


@dataclass(frozen=True)
class Sink:
    root: str
    add: Callable[..., None]
    allow: Allowlist

    def allows(self, kind, rel, symbol, line):
        return self.allow.allows(kind, rel, symbol, line)
