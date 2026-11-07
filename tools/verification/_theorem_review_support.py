# SPDX-License-Identifier: Apache-2.0
"""Fixtures shared by the theorem-review cases."""

from __future__ import annotations

from dataclasses import dataclass

from _fingerprint import (
    assumption_digest,
    canonical_digest,
    fingerprint_theorem,
    theorem_premises,
    theorem_review_digests,
)
from _review import (
    Basis,
    root_completeness,
    theorem_assurance,
)


UNIT = "http_profile.freshness_window"


def theorem(**overrides) -> dict:
    entry = {
        "id": "THM-0001",
        "title": "Freshness admission implies the accepted window is current",
        "statement": "Every admitted request satisfies the skew-widened window constraints.",
        "security_consequence": "A request cannot be admitted on stale freshness evidence.",
        "scope": "Freshness admission only; not signature validity or replay uniqueness.",
        "owner": UNIT,
        "review_requirement": "Owner security-specification review",
        "supported_by": [f"unit://{UNIT}"],
        "depends_on": [],
    }
    entry.update(overrides)
    return entry


def registry(*rows, roots: list[str] | None = None) -> dict:
    return {
        "schema_version": 1,
        "root_theorems": list(roots or []),
        "theorem": list(rows or (theorem(),)),
    }


def review_for(current: dict, subject: str = "THM-0001", semantic: dict | None = None) -> dict:
    """The record a reviewer commits after reading the claim as it stands — and, when
    `semantic` is given, the supporting evidence it was read against."""
    record = {
        "axis": "specification",
        "subject": subject,
        "reviewed_fingerprint": current["fingerprint"],
        "components": current["components"],
        "reviewer": "owner@example.com",
    }
    if semantic is not None:
        record["review_digest"] = semantic["fingerprint"]
        record["review_components"] = semantic["components"]
    return record


def unit_fp(**overrides) -> dict:
    """A supporting unit's fingerprint with one value per kind of component: semantic
    (source, test selection, proved symbols) and evidence-only (toolchain, lane identity,
    policy revision)."""
    components = {
        "encoding_version": 10,
        "unit_id": UNIT,
        "class": "V1",
        "source_inputs": {"src/freshness.rs": "sha256:aaa"},
        "test_selection": {"symbols": ["freshness::tests::admits_inside_window"]},
        "proved_symbols": ["check_freshness"],
        "trusted_assumptions": {},
        "governing_boundaries": {},
        "toolchain_identity": {"verus": "0.2026.09.01"},
        "verus_lane_identity": {"tools/verification/verify-verus": "sha256:bbb"},
        "review_policy_revision": "policy-7",
    }
    components.update(overrides)
    return {"unit_id": UNIT, "fingerprint": canonical_digest(components), "components": components}


UNIT_FP = unit_fp()


def semantics(doc: dict, premises: dict, units: dict | None = None) -> dict:
    return theorem_review_digests(
        doc, fingerprints(doc), premises, {UNIT: UNIT_FP} if units is None else units
    )


def fingerprints(doc: dict) -> dict[str, dict]:
    return {row["id"]: fingerprint_theorem(row, doc) for row in doc["theorem"]}


# --- composition ------------------------------------------------------------------


def premise_chain(bottom_statement: str) -> dict:
    return registry(
        theorem(id="THM-0001", statement=bottom_statement),
        theorem(id="THM-0002", depends_on=["THM-0001"]),
        theorem(id="THM-0003", depends_on=["THM-0002"]),
    )


# --- the conjunction: no axis may carry the others ----------------------------------


#: Every subject backed by the owner-approval ledger: the fixtures below test the other
#: axes, and `test_*premise*`/`test_*ledger*` test this one.
class Backing(dict):
    """A ledger answer for every subject, `default` unless overridden."""

    def __init__(self, default=(True, "fixture ledger signs it"), **overrides):
        super().__init__(overrides)
        self.default = default

    def get(self, key, fallback=None):
        return super().get(key, self.default)


BACKED = Backing()


def no_premises(doc) -> dict:
    return {row["id"]: {} for row in doc["theorem"]}


def assurance(doc, *, unit_state="FRESH", reviewed=True, **kwargs):
    fps = fingerprints(doc)
    digests = semantics(doc, no_premises(doc))
    reviews = {}
    if reviewed:
        reviews = {
            ("specification", tid): review_for(fp, tid, digests[tid]) for tid, fp in fps.items()
        }
    states = {UNIT: (unit_state, "test fixture")}
    return theorem_assurance(
        doc, Basis(fps, reviews, states, no_premises(doc), BACKED, digests), **kwargs
    )


# --- the premise axis: REVIEWED covers the claim AND its premises (Ruling 34 §7 A) ------


ASM = {"id": "ASM-0001", "description": "The clock is monotone.", "scope": [f"unit://{UNIT}"]}


def assumption_review(entry: dict) -> dict:
    digest = assumption_digest(entry)
    return {
        "axis": "assumption",
        "subject": entry["id"],
        "reviewed_fingerprint": digest,
        "components": {"assumption_entry": digest},
        "reviewer": "owner@example.com",
    }


def premise_assurance(*, premise_entry=ASM, record=True, backing=BACKED):
    """The owner reviewed THM-0001 over premise `ASM`; the tree now has `premise_entry`."""
    doc = registry()
    fps = fingerprints(doc)
    read_at = semantics(doc, {"THM-0001": {ASM["id"]: assumption_digest(ASM)}})
    reviews = {("specification", "THM-0001"): review_for(fps["THM-0001"], semantic=read_at["THM-0001"])}
    if record:
        reviews[("assumption", ASM["id"])] = assumption_review(ASM)
    premises = {"THM-0001": {premise_entry["id"]: assumption_digest(premise_entry)}}
    return theorem_assurance(
        doc,
        Basis(
            fps, reviews, {UNIT: ("FRESH", "fixture")}, premises, backing,
            semantics(doc, premises),
        ),
    )["THM-0001"]


# --- two axes: REVIEW_CURRENT and EVIDENCE_ESTABLISHED (Ruling 35 §3) -------------------


@dataclass(frozen=True)
class Scene:
    """What the owner read (`read_*`) and what the tree now holds (`now_*`); an unset `now_*`
    is the same as what was read."""

    read_units: dict | None = None
    now_units: dict | None = None
    read_doc: dict | None = None
    now_doc: dict | None = None
    read_premises: dict | None = None
    now_premises: dict | None = None


def _assumption_reviews(now_premises: dict) -> dict:
    return {
        ("assumption", asm): {
            "axis": "assumption",
            "subject": asm,
            "reviewed_fingerprint": now_premises["THM-0001"][asm],
            "components": {"assumption_entry": now_premises["THM-0001"][asm]},
            "reviewer": "owner@example.com",
        }
        for asm in (now_premises.get("THM-0001") or {})
    }


def two_axis(*, unit_state="FRESH", record=True, **scene):
    """The owner reviewed THM-0001 over the `Scene`'s `read_*`; the tree now has `now_*`.
    Every premise is reviewed and backed, so only the semantic and evidence axes are under
    test."""
    world = Scene(**scene)
    read_doc = world.read_doc or registry()
    now_doc = world.now_doc or read_doc
    read_premises = (
        world.read_premises if world.read_premises is not None else no_premises(read_doc)
    )
    now_premises = world.now_premises if world.now_premises is not None else read_premises
    read_units = world.read_units or {UNIT: UNIT_FP}
    now_units = world.now_units or read_units
    read_at = theorem_review_digests(read_doc, fingerprints(read_doc), read_premises, read_units)
    reviews = {}
    if record:
        reviews[("specification", "THM-0001")] = review_for(
            fingerprints(read_doc)["THM-0001"], semantic=read_at["THM-0001"]
        )
    reviews.update(_assumption_reviews(now_premises))
    now_fps = fingerprints(now_doc)
    return theorem_assurance(
        now_doc,
        Basis(
            now_fps,
            reviews,
            {UNIT: (unit_state, "fixture")},
            now_premises,
            BACKED,
            theorem_review_digests(now_doc, now_fps, now_premises, now_units),
        ),
    )["THM-0001"]


def attested(fp: dict):
    from _graph import Attestation

    return {UNIT: Attestation(unit_id=UNIT, fingerprint=fp["fingerprint"], components=fp["components"])}


# --- root completeness: the second property, ADR-MCPRE-059 §28.8 ---------------------
#
# Freshness and completeness are different questions, and the controls below exist to keep
# them from being answered by one number. The pair that matters is the fourth and fifth: a
# repository whose evidence is entirely honest and current, whose ratified system promise is
# nevertheless open, must stay GREEN in ordinary CI and RED in closure mode. If the first
# half fails, recording a gap costs a red build and people stop recording gaps.


def rooted(*rows, roots, **kwargs):
    """Assurance plus the root-completeness derivation over the same registry."""
    doc = registry(*rows, roots=roots)
    return root_completeness(doc, assurance(doc, **kwargs))


# --- the premise-closure rule (r12 defect D) ------------------------------------------


def closure_fixture(*entries: dict) -> dict:
    """THM-A on unit `a`, THM-B on unit `b`; both cross `boundary.k`, only `a` is named."""
    theorems = {
        "theorem": [
            {"id": "THM-A", "supported_by": ["unit://a"]},
            {"id": "THM-B", "supported_by": ["unit://b"]},
        ]
    }
    registry = {"assumption": list(entries)}
    fps = {}
    for unit in ("a", "b"):
        named = {
            e["id"]: assumption_digest(e)
            for e in entries
            if f"unit://{unit}" in e.get("scope", [])
        }
        fps[unit] = {
            "components": {
                "trusted_assumptions": named,
                "governing_boundaries": {"boundary.k": "sha256:k"},
            }
        }
    return theorem_premises(theorems, fps, registry)


def premise_entry(asm_id: str, scope: list[str], **extra) -> dict:
    return {"id": asm_id, "scope": scope, "premise_class": "assumed", **extra}
