# SPDX-License-Identifier: Apache-2.0
"""The census's vocabulary: what a control IS and which kinds of control exist.

`_controls` enumerates the controls; every enumerator builds its results from this module,
so the identity a registry selector names has one definition.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Every control kind this module enumerates, with the ecosystem/lane each belongs to.
#: A census reports coverage per kind, so an ecosystem that stops being discoverable shows
#: up as a zero rather than as an absence nobody counted.
KINDS: dict[str, str] = {
    "rust-test": "rust",
    "rust-doctest": "rust",
    "pytest": "python",
    "vitest": "typescript",
    "structural": "structural-lane",
    "mutation": "mutation-lane",
    "measurement": "measured-lane",
    "gate": "gate-lane",
}


@dataclass(frozen=True)
class Control:
    """One executable control, identified as the registry would have to name it."""

    #: The project the identity is unique inside — the Bazel package of a Rust crate root,
    #: the python or node project directory, or "" for a control a registry carries.
    #: `src/lib.rs#error::tests::the_token_is_frozen` can exist in two crates at once, and a
    #: census joining on the bare identity would report one of them as claimed on the
    #: strength of the other's registration.
    project: str
    identity: str
    kind: str
    carrier: str
    line: int
    #: What a reader needs in order to not misread the control — a doctest's fence modes,
    #: so that a compile refusal is never mistaken for behavioural evidence.
    note: str = ""

    def to_json(self) -> dict:
        return {
            "project": self.project,
            "identity": self.identity,
            "kind": self.kind,
            "ecosystem": KINDS[self.kind],
            "carrier": self.carrier,
            "line": self.line,
            "note": self.note,
        }
