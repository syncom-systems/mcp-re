# SPDX-License-Identifier: Apache-2.0
"""The register (`docs/architecture/control-dispositions.md`) and the registry must agree."""

from __future__ import annotations

import collections
import re

import _registries
from _controls import REPO_ROOT
from _controls_cases_support import load_census_tool
import _census

_REGISTER = REPO_ROOT / "docs" / "architecture" / "control-dispositions.md"


def test_the_register_and_the_registry_agree_in_both_directions():
    """Every declaration has a record, and every record is declared.

    The gate checks both. This control checks that the live pair actually agrees, so the
    assertion goes red on a dead record as well as on a missing one — *a dead row hides the
    next live one* is a defect this repository has already met in another register.
    """
    raw = _registries.document("control-dispositions")
    declared = {entry["id"] for entry in raw.get("proposition", [])} | {
        row["reason_family"] for row in raw.get("disposition", []) if row.get("reason_family")
    }
    found = set(re.findall(r"^## (NP-\d+|ND-\d+)", _REGISTER.read_text(), re.M))
    assert declared, "nothing declared; the registry went dark"
    assert found - declared == set(), sorted(found - declared)
    assert declared - found == set(), sorted(declared - found)


def _register_sections() -> dict[str, list[str]]:
    """Each `## NP-…` record in the register, as its id mapped to its body lines."""
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in _REGISTER.read_text().splitlines():
        heading = re.match(r"^## (NP-\d+|ND-\d+)", line)
        if heading:
            current = sections.setdefault(heading.group(1), [])
        elif current is not None:
            current.append(line)
    return sections


def _wrapped_paragraph(body: list[str], start: int) -> str:
    """The field line at `body[start]` and the lines wrapped under it, as one string."""
    paragraph = [body[start]]
    for follower in body[start + 1 :]:
        if not follower.strip() or follower.startswith("**"):
            break
        paragraph.append(follower)
    return " ".join(paragraph)


def _control_paragraph(body: list[str]) -> tuple[str, bool] | None:
    """A record's `**Control(s):**` paragraph, and whether it was written in the singular.

    The paragraph runs from the field line to the next blank line or the next `**Field:**`,
    because a record naming several carriers wraps and the wrapped lines carry counts too.
    """
    for index, line in enumerate(body):
        if line.startswith(("**Control:**", "**Controls:**")):
            return _wrapped_paragraph(body, index), line.startswith("**Control:**")
    return None


def _count_drift(entry_id: str, body: list[str], held: int) -> str | None:
    """How a record's stated control count disagrees with the registry, or None."""
    paragraph = _control_paragraph(body)
    if paragraph is None:
        return f"{entry_id}: no **Control(s):** paragraph"
    text, singular = paragraph
    stated = [int(number) for number in re.findall(r"\((\d+)\)", text)]
    if stated:
        return None if sum(stated) == held else (
            f"{entry_id}: record states {sum(stated)}, registry holds {held}"
        )
    if singular and held != 1:
        return f"{entry_id}: record is singular **Control:**, registry holds {held}"
    return None


def test_each_record_states_the_number_of_controls_the_registry_holds():
    """A count in the durable record is a claim about the registry, so it is checked.

    `test_the_register_and_the_registry_agree_in_both_directions` goes red on a dead or a
    missing record. It says nothing about a record that EXISTS and states a number the
    registry contradicts, which is how the argv family's records came to state `cli.rs`'s
    own test module as each proposition's total while the registry held the `cli/*_flags*`
    submodules' rows as well. Sixteen records drifted that way before anything asked.

    Two claims are read, and only claims:

      * a paragraph carrying parenthesised counts claims their SUM;
      * a paragraph written `**Control:**`, singular, claims exactly ONE.

    A plural paragraph with no number claims nothing numeric and is outside this assertion;
    inventing a claim for it is not this control's business.
    """
    raw = _registries.document("control-dispositions")
    rows = collections.Counter(
        row["proposition"]
        for row in raw.get("disposition", [])
        if row.get("decision") == "new-proposition" and row.get("proposition")
    )
    sections = _register_sections()
    assert sections, "no records parsed; the register went dark"
    # A proposition with no record is the id-set control's to report, not this one's.
    drifts = (
        _count_drift(entry["id"], sections[entry["id"]], rows.get(entry["id"], 0))
        for entry in raw.get("proposition", [])
        if entry["id"] in sections
    )
    drifted = [drift for drift in drifts if drift is not None]
    assert not drifted, "\n".join(sorted(drifted))


def _flatten(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def test_a_records_heading_and_its_registry_title_are_one_fact():
    """The `##` heading and the `[[proposition]].title` are two spellings of one thing.

    They drift silently and in the direction that matters: NP-112's title was widened to
    "A host OR CLIENT signer …" to cover three `mcp-re-client` rows the record's heading,
    its `**Controls:**` line and its three-clause statement all still described nothing
    about. The registry then said a record covered six controls while the record described
    three, which is the defect no count check reaches — a widened title is not a wrong
    number, it is a record claiming a scope it never wrote down.

    Compared case- and punctuation-insensitively: the heading is lowercase prose and the
    title is a sentence, and neither spelling is the defect.
    """
    headings = dict(re.findall(r"^## (NP-\d+) — (.+)$", _REGISTER.read_text(), re.M))
    raw = _registries.document("control-dispositions")
    assert headings, "no headings parsed; the register went dark"
    disagreeing = [
        f"{entry['id']}: heading {headings[entry['id']]!r} vs title {entry['title']!r}"
        for entry in raw.get("proposition", [])
        if entry["id"] in headings and _flatten(headings[entry["id"]]) != _flatten(entry["title"])
    ]
    assert not disagreeing, "\n".join(sorted(disagreeing))


def test_an_unknown_key_in_the_registry_is_refused():
    """The registry's header promises it, so something has to keep the promise.

    Until this check existed the loader ignored an unknown key, so a typo in `reason_family`
    read as an ABSENT reason and a `not-evidence` row passed the ADR-069 D3 check with
    nothing behind it. Perturbed rather than asserted: a schema check that has never seen a
    bad key is a schema check nobody has run.
    """
    censor = load_census_tool()
    clean = {"disposition": [{"id": "CD-X", "decision": "not-evidence"}], "proposition": []}
    assert censor._schema_failures(clean) == []
    typo = {"disposition": [{"id": "CD-X", "decision": "not-evidence", "reson_family": "ND-001"}]}
    assert any("reson_family" in problem for problem in censor._schema_failures(typo))


def test_a_severity_outside_the_vocabulary_is_refused():
    """ADR-MCPRE-068 §4.1's words, because a consequence is compared across records."""
    censor = load_census_tool()
    entries = _census.propositions()
    assert entries, "no propositions; the registry went dark"
    assert all(e.get("consequence") in ("medium", "high", "critical") for e in entries)
    bad = {"proposition": [{"id": "NP-X", "consequence": "severe"}], "disposition": []}
    assert any("severe" in problem for problem in censor._schema_failures(bad))
