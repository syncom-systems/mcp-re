# SPDX-License-Identifier: Apache-2.0
"""The selftest's scenarios: each is a registry, a measured population and a basis, with the defect
it must produce (or `None` for none)."""

from __future__ import annotations

from dataclasses import dataclass, field

from _assurance_obligation.succession import Basis

BASE_ROW = {
    "unit": "u",
    "obligation": "a mutation:// falsifier",
    "effective_severity": "high",
    "direct_consequence_severity": "high",
    "inherited_severity": "none",
    "root_reachable": False,
    "status": "unreviewed",
}
NOW = {
    "u": {
        "effective_severity": "high",
        "direct_consequence_severity": "high",
        "inherited_severity": "none",
        "root_reachable": False,
    }
}
REG = {"u": dict(BASE_ROW)}


@dataclass(frozen=True)
class Scenario:
    label: str
    measured: dict
    registry: dict
    basis: Basis
    expect: str | None


def ratchet_scenarios() -> list[Scenario]:
    raised = {"u": {**NOW["u"], "effective_severity": "critical"}}
    stale = {"u": {**NOW["u"], "root_reachable": True}}
    returned = {"u": {**BASE_ROW, "status": "reviewed-action-required"}}
    return [
        Scenario("a registered owing unit passes", NOW, REG, Basis(REG, {}, {}), None),
        Scenario("an UNregistered owing unit fails", NOW, {}, Basis({}, {}, {}), "CLOSED to new work"),
        Scenario("a registered unit that stopped owing fails", {}, REG, Basis(REG, {}, {}), "no longer owed"),
        Scenario("a severity that MOVED is not covered by the old row", raised, REG, Basis(REG, {}, {}), "not the one this"),
        Scenario("a stale root_reachable is refused", stale, REG, Basis(REG, {}, {}), "root_reachable"),
        Scenario("the registry may not GROW", NOW, REG, Basis({}, {}, {}), "GREW against the base"),
        Scenario("the registry MAY shrink", {}, {}, Basis(REG, {}, {}), None),
        Scenario("a status may not return to unreviewed", NOW, REG, Basis(returned, {}, {}), "one-way"),
        Scenario("a base without the registry checks the registry but not the ratchet", NOW, REG, Basis(None, {}, {}), None),
    ]


@dataclass(frozen=True)
class Decomposition:
    """A wide obligation split into two narrow ones, the shape every succession scenario varies."""

    wide: dict = field(default_factory=lambda: {**BASE_ROW, "unit": "wide", "effective_severity": "critical"})
    base_paths: dict = field(default_factory=lambda: {"wide": {"src/one.py", "src/two.py"}})
    now_paths: dict = field(default_factory=lambda: {"a": {"src/one.py"}, "b": {"src/two.py"}})

    @staticmethod
    def narrow(unit: str, **over) -> dict:
        row = {
            **BASE_ROW,
            "unit": unit,
            "effective_severity": "high",
            "succeeds": "wide",
            "decomposition_ref": "README.md",
        }
        row.update(over)
        return row

    def split(self) -> dict:
        return {"a": self.narrow("a"), "b": self.narrow("b")}

    @staticmethod
    def measured() -> dict:
        return {
            "a": {**NOW["u"], "effective_severity": "high"},
            "b": {**NOW["u"], "effective_severity": "high"},
        }


def refusal_succession_scenarios() -> list[Scenario]:
    d = Decomposition()
    split, measured, was = d.split(), d.measured(), {"wide": d.wide}
    basis = Basis(was, d.base_paths, d.now_paths)
    half = {**split, "b": {k: v for k, v in split["b"].items() if k != "succeeds"}}
    missing_ref = {**split, "a": d.narrow("a", decomposition_ref="docs/nope-not-here.md")}
    itself = {**split, "a": d.narrow("a", succeeds="a")}
    still_owes = {**measured, "wide": {**NOW["u"], "effective_severity": "critical"}}
    return [
        Scenario("half a succession is refused", measured, half, basis, "only one half"),
        Scenario("a decomposition_ref this tree lacks is refused", measured, missing_ref, basis, "does not hold"),
        Scenario("succeeding oneself is refused", measured, itself, basis, "succeeds itself"),
        Scenario("a predecessor the base did not hold is refused", measured, split,
                 Basis({}, d.base_paths, d.now_paths), "does not hold"),
        Scenario("a predecessor that still owes is refused", still_owes, split, basis, "still owes"),
    ]


def bound_succession_scenarios() -> list[Scenario]:
    d = Decomposition()
    split, measured, was = d.split(), d.measured(), {"wide": d.wide}
    basis = Basis(was, d.base_paths, d.now_paths)
    raised = {**measured, "a": {**NOW["u"], "effective_severity": "critical"}}
    raised_rows = {**split, "a": d.narrow("a", effective_severity="critical")}
    high_wide = {"wide": {**d.wide, "effective_severity": "high"}}
    new_code = {**d.now_paths, "b": {"src/two.py", "src/brand-new.py"}}
    missing_ref = {**split, "a": d.narrow("a", decomposition_ref="docs/nope-not-here.md")}
    return [
        Scenario("a successor above the predecessor's severity is refused", raised, raised_rows,
                 Basis(high_wide, d.base_paths, d.now_paths), "above the predecessor"),
        Scenario("a successor covering code the predecessor did not is refused", measured, split,
                 Basis(was, d.base_paths, new_code), "did not cover"),
        Scenario("an unavailable base refuses the succession rather than assuming it", measured, split,
                 Basis(None, d.base_paths, d.now_paths), "cannot be checked"),
        Scenario("an unavailable unit registry refuses it rather than assuming it", measured, split,
                 Basis(was, None, d.now_paths), "cannot be compared"),
        Scenario("a row ALREADY IN THE BASE is not re-validated — the merge spent it", measured, split,
                 Basis({**was, **split}, d.base_paths, d.now_paths), None),
        Scenario("a malformed succession does not also buy growth", measured, missing_ref, basis,
                 "GREW against the base"),
    ]


def succession_scenarios() -> list[Scenario]:
    """SUCCESSION, in both directions. Every clause is a way a decomposition could smuggle in
    an obligation the base registry never held, so every clause is tested for refusing it
    AND the whole mechanism is tested for admitting the legitimate case — a gate that only
    ever refuses would make Phase 1 impossible in exactly the way the rule exists to avoid."""
    d = Decomposition()
    admitted = Scenario("a valid succession is admitted", d.measured(), d.split(),
                        Basis({"wide": d.wide}, d.base_paths, d.now_paths), None)
    return [admitted] + refusal_succession_scenarios() + bound_succession_scenarios()


ROW_HEAD = ('unit = "u"\nobligation = "x"\neffective_severity = "high"\n'
            'direct_consequence_severity = "high"\ninherited_severity = "none"\n'
            'root_reachable = false\n')


def parser_cases() -> list[tuple[str, str, str]]:
    """A mistyped declaration must not read as an absent one."""
    return [
        ("an unknown key", ROW_HEAD + 'status = "unreviewed"\nnope = 1\n', "unknown obligation field"),
        ("a missing key", 'unit = "u"\nobligation = "x"\n', "entry is missing"),
        ("an unknown status", ROW_HEAD + 'status = "fine-actually"\n', "not one of"),
        ("an empty obligation", ROW_HEAD.replace('obligation = "x"', 'obligation = "  "') + 'status = "unreviewed"\n',
         "names the obligation"),
    ]
