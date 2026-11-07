# SPDX-License-Identifier: Apache-2.0
"""`ratified_as` — the field that was declared and read by nobody — and the record-id checks.

Setting `ratified_as = "THM-9999-does-not-exist"` on all 169 proposition rows produced
ZERO failures, and the human report then printed 169 resolved propositions. A metric a
field edit can satisfy has measured nothing. Every control below is a FALSIFIER: it
doctors a registry in memory — never the committed policy files — and asserts the check
sees the lie, then asserts the honest shape passes.
"""

from __future__ import annotations

import _census
from _controls_cases_support import REPORT, load_census_tool

#: A unit id that claims a control in the real join, and one that claims nothing. The first
#: is taken from the live census so the fixture cannot drift into naming a dead unit.
_CLAIMING_UNIT = REPORT.claims[0].unit
_CLAIMED = REPORT.claims[0].control
_SILENT_UNIT = "u.claims.nothing"


def _ratified(entry, rows=(), units=(), theorems=()):
    """One proposition's `ratified_as` verdict, against a doctored world."""
    censor = load_census_tool()
    report = _census.Census(
        controls=[], claims=list(REPORT.claims), stale=[], dispositions=list(rows)
    )
    ids = {_CLAIMING_UNIT, _SILENT_UNIT} | set(units)
    return censor.ratification_by_entry(report, [entry], ids, list(theorems))[entry["id"]]


def _row(control, project="", identity=""):
    return _census.Disposition(
        id="NP-TEST-01",
        project=project or (control.project if control else ""),
        control=identity or (control.identity if control else ""),
        decision="new-proposition",
        reason_family="",
        recorded="2026-09-19",
        proposition="NP-TEST",
    )


def test_a_ratified_as_naming_no_declared_owner_is_refused():
    """The defect this check exists about, reproduced at its own scale.

    A theorem id that does not exist is indistinguishable, to every other check in this
    file, from one that does — which is why the whole 169-row registry could be marked
    resolved without a single failure. Asserted against the LIVE registry doctored in
    memory, so the number is the real one.
    """
    censor = load_census_tool()
    entries = [dict(entry, ratified_as="THM-9999-does-not-exist") for entry in _census.propositions()]
    verdicts = censor.ratification_by_entry(REPORT, entries)
    assert len(verdicts) == len(entries)
    assert all(v for v in verdicts.values()), "a nonexistent owner passed"
    assert all("neither a declared unit nor a theorem" in v[0] for v in verdicts.values())
    honest = censor.ratification_by_entry(REPORT, _census.propositions())
    assert not any(honest.values()), "the committed registry must stay clean"


def test_a_unit_owner_must_claim_every_cited_control_and_not_merely_one():
    """The at-least-one form would let a 37-control proposition read as owned by 1/37.

    A row survives only for a control nothing claims — the census refuses a row about a
    claimed control as an orphan — so a resolved proposition with any remaining row is a
    proposition whose controls still establish nothing anybody states.
    """
    entry = {"id": "NP-TEST", "ratified_as": _CLAIMING_UNIT}
    assert _ratified(entry) == [], "a resolved proposition with no remaining row is legal"
    orphaned = _row(None, project="mcp-re-proxy", identity="src/lib.rs#nothing::claims::this")
    problems = _ratified(entry, rows=[_row(_CLAIMED), orphaned])
    assert len(problems) == 1, problems
    assert "owns 1 of 2 cited control(s); 1 remain(s)" in problems[0], problems


def test_a_theorem_owner_needs_a_support_closure_that_claims_something():
    """The theorem EXISTING is not the check — a title resolves nothing.

    Three shapes: no support at all, support that reaches only a unit whose battery
    selects nothing, and support reached transitively through `depends_on`. The third must
    PASS, because a composite claim may rest entirely on the theorems below it and refusing
    it would push a resolution back into the flat form ADR-069 §5 is trying to avoid.
    """
    entry = {"id": "NP-TEST", "ratified_as": "THM-T1"}
    empty = _ratified(entry, theorems=[{"id": "THM-T1", "supported_by": [], "depends_on": []}])
    assert empty and "empty support closure" in empty[0], empty
    silent = _ratified(
        entry, theorems=[{"id": "THM-T1", "supported_by": [f"unit://{_SILENT_UNIT}"],
                          "depends_on": []}]
    )
    assert silent and "claims no control at all" in silent[0], silent
    transitive = [
        {"id": "THM-T1", "supported_by": [], "depends_on": ["THM-T2"]},
        {"id": "THM-T2", "supported_by": [f"unit://{_CLAIMING_UNIT}"], "depends_on": []},
    ]
    assert _ratified(entry, theorems=transitive) == []


def test_ratified_as_names_exactly_one_owner():
    """The canonical owner, alone. The per-control claims carry any others.

    A second name here would be a second place the same fact is written, with nothing
    holding the two in agreement — and a list or a padded string resolves to no id at all,
    so without this check it would fall through to whatever the resolver made of it.
    """
    assert _ratified({"id": "NP-TEST", "ratified_as": _CLAIMING_UNIT}) == []
    as_list = _ratified({"id": "NP-TEST", "ratified_as": [_CLAIMING_UNIT]})
    assert as_list and "names ONE canonical owner" in as_list[0], as_list
    for value in (f"{_CLAIMING_UNIT}, {_SILENT_UNIT}", f"{_CLAIMING_UNIT};x",
                  f"{_CLAIMING_UNIT}+x", f"{_CLAIMING_UNIT} "):
        problems = _ratified({"id": "NP-TEST", "ratified_as": value})
        assert problems and "not a single id" in problems[0], (value, problems)


def test_closure_additionally_requires_the_proposition_population_to_be_empty():
    """ADR-069 §5's step-2 debt is part of the closure criterion, not a report line.

    `--gate` must NOT gain this: step 2 runs through theorem architecture on its own
    timescale, and failing every merge on it would be pressure to widen an existing unit to
    swallow the proposition — which §5 forbids in terms.
    """
    censor = load_census_tool()
    entries = _census.propositions()
    assert entries, "no propositions; the registry went dark"
    merge_time = censor.failures(REPORT)
    release_time = censor.closure_failures(REPORT)
    assert not [p for p in merge_time if p.startswith("unresolved proposition:")]
    unresolved = [p for p in release_time if p.startswith("unresolved proposition:")]
    assert len(unresolved) == len(entries), (len(unresolved), len(entries))


def test_a_resolved_proposition_is_exempt_from_the_citation_check_and_a_broken_one_is_not():
    """The resolved state has to be REACHABLE, and the exemption may not be an escape.

    A proposition whose controls have all been claimed has no rows left, which is exactly
    the shape "declared and no control cites it" refuses. Exempting it is what lets step 2
    finish; exempting it on a `ratified_as` that does not resolve would hand every entry a
    one-word opt-out of the check, which is the defect one level up.
    """
    censor = load_census_tool()
    report = _census.Census(controls=[], claims=list(REPORT.claims), stale=[], dispositions=[])
    holder = [{"id": "NP-TEST", "ratified_as": _CLAIMING_UNIT}]
    censor.propositions = lambda: holder
    censor.units = lambda: [{"id": _CLAIMING_UNIT}]
    censor._record = lambda _anchor: ""
    cited = [p for p in censor.failures(report) if "no control cites it" in p]
    assert cited == [], cited
    holder[0] = {"id": "NP-TEST", "ratified_as": "THM-9999-does-not-exist"}
    problems = censor.failures(report)
    assert [p for p in problems if "no control cites it" in p] == [
        "NP-TEST: declared and no control cites it"
    ]
    assert any("neither a declared unit nor a theorem" in p for p in problems)


def test_an_id_carried_by_two_records_is_refused():
    """An id is how a disposition or a proposition is cited. Two records under one id are
    two decisions a citation cannot tell apart, and parallel changes took eight disposition
    ids twice before this check existed."""
    censor = load_census_tool()
    row = REPORT.dispositions[0]
    twice = _census.Census(controls=[], claims=list(REPORT.claims), stale=[], dispositions=[row, row])
    entry = _census.propositions()[0]
    censor.propositions = lambda: [entry, entry]
    problems = censor.failures(twice)
    assert f"disposition id {row.id} is carried by 2 records; give every record but the first a fresh id" in problems, problems
    assert any(p.startswith(f"proposition id {entry['id']} is carried by 2") for p in problems), problems
    once = _census.Census(controls=[], claims=list(REPORT.claims), stale=[], dispositions=[row])
    censor.propositions = lambda: [entry]
    assert not [p for p in censor.failures(once) if "is carried by" in p]
