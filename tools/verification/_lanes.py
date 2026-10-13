# SPDX-License-Identifier: Apache-2.0
"""The lane catalogue: one row per verification lane, and the one answer to "does this unit
claim it".

Every fact a reader needs about a lane is a column here: the entry point `verify` runs, the
execution phase it belongs to, whether it produces evidence or is a precondition for
trusting evidence, the evidence URI scheme that claims it, which tiers it applies to,
whether the unit's own URI is what requires it, whether a scoped run confines it, and which
evidence classes it establishes and falsifies. `verify`, `_compose`, `_evidence_class`, the
lanes, the fingerprint and the two merge gates read these rows; none of them restates one.

A LEAF MODULE. It imports nothing from this package, because `_evidence_class` and
`_assurance_graph` are read by the manifest loader and the loader reads them: a catalogue
that imported the loader would make every one of them part of an import cycle.

`generated-model` has no URI of its own. It is the freshness precondition of `lean://`
evidence — a Lean theorem about a stale model is a theorem about a different tree — so its
claiming scheme is `lean://` and it establishes and falsifies no class.

`verus` is the one formal lane whose requirement is the tier alone: a V1 or V3 unit owes a
Verus record whether or not it declares `verus://`. Every other formal lane is required
only where the unit declares its scheme.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

TIERS_ALL = frozenset({"V0", "V1", "V2", "V3"})


@dataclass(frozen=True)
class Lane:
    """One lane. `formal` lanes produce evidence about the code; the others are
    preconditions for trusting it and belong to the composer, never to a phase."""

    name: str
    script: str
    formal: bool
    phase: str | None = None
    scheme: str | None = None
    tiers: frozenset[str] = frozenset()
    uri_required: bool = True
    scopable: bool = False
    establishes: tuple[str, ...] = ()
    falsifies: tuple[str, ...] = ()


#: In dispatch order. `verify` runs them in this order and reports them in it.
LANES: tuple[Lane, ...] = (
    Lane("assumptions", "check-assumptions", formal=False),
    Lane(
        "generated-model", "check-generated", formal=True, phase="extraction",
        scheme="lean://", tiers=frozenset({"V2", "V3"}),
    ),
    Lane(
        "test", "verify-tests", formal=True, phase="host", scheme="test://",
        tiers=TIERS_ALL, scopable=True, establishes=("tested",),
    ),
    # A V0 claim's negative battery: does deleting the check a theorem names actually turn a
    # declared control red? It falsifies `tested`; the battery it names establishes it.
    Lane(
        "mutation", "verify-mutations", formal=True, phase="host", scheme="mutation://",
        tiers=TIERS_ALL, scopable=True, falsifies=("tested",),
    ),
    # A structural claim's falsifier is a COMPILATION that must be refused, and a measured
    # one's is an apparatus that must still MOVE; neither is a test going red.
    Lane(
        "structural", "verify-structural", formal=True, phase="host",
        scheme="structural://", tiers=TIERS_ALL, scopable=True,
        establishes=("structural",), falsifies=("structural",),
    ),
    # `measured` falsifies nothing here: its apparatus control is a declared field, not a
    # probe URI, and a measured proposition takes no mutation obligation (ADR-MCPRE-068
    # Ruling 4).
    Lane(
        "measured", "verify-measured", formal=True, phase="host", scheme="measured://",
        tiers=TIERS_ALL, scopable=True, establishes=("measured",),
    ),
    Lane(
        "verus", "verify-verus", formal=True, phase="host", scheme="verus://",
        tiers=frozenset({"V1", "V3"}), uri_required=False, scopable=True,
        establishes=("proved",), falsifies=("proved",),
    ),
    # The extraction lanes judge the one extracted model as a whole, so a scoped run runs
    # them in full and the composer reads only the selected units' records.
    Lane(
        "lean", "verify-lean", formal=True, phase="extraction", scheme="lean://",
        tiers=frozenset({"V2", "V3"}), establishes=("proved",), falsifies=("proved",),
    ),
)

BY_NAME: dict[str, Lane] = {lane.name: lane for lane in LANES}
FORMAL: tuple[Lane, ...] = tuple(lane for lane in LANES if lane.formal)
HYGIENE: tuple[Lane, ...] = tuple(lane for lane in LANES if not lane.formal)


def phase_lanes(phase: str) -> frozenset[str]:
    """The formal lanes the named execution phase runs."""
    return frozenset(lane.name for lane in FORMAL if lane.phase == phase)


HOST_LANES = phase_lanes("host")
EXTRACTION_LANES = phase_lanes("extraction")
PHASES: dict[str, frozenset[str]] = {"host": HOST_LANES, "extraction": EXTRACTION_LANES}
SCOPABLE_LANES = frozenset(lane.name for lane in FORMAL if lane.scopable)


def claims_scheme(unit: dict, scheme: str) -> bool:
    """Whether any evidence URI the unit declares is in `scheme` (e.g. `test://`)."""
    return any(str(entry).startswith(scheme) for entry in unit.get("evidence", []))


def claims(unit: dict, lane: str) -> bool:
    """Whether the unit's declared evidence claims `lane`.

    `generated-model` is claimed by `lean://`. A lane with no scheme is claimed by no unit.
    """
    scheme = BY_NAME[lane].scheme
    return scheme is not None and claims_scheme(unit, scheme)


def required(unit: dict, lane: str) -> bool:
    """Whether the manifest requires `lane`'s evidence of this unit.

    The tier decides whether the lane applies at all; for every lane but `verus` the unit's
    own declared URI then decides whether it is asked. A V0 unit with no battery claims none,
    and requiring one would demand evidence the manifest never promised.
    """
    row = BY_NAME[lane]
    if not row.formal or unit["class"] not in row.tiers:
        return False
    return claims(unit, lane) if row.uri_required else True


def _schemes_by_class(column: str) -> dict[str, tuple[str, ...]]:
    out: dict[str, tuple[str, ...]] = {}
    for lane in FORMAL:
        for evidence_class in getattr(lane, column):
            out[evidence_class] = (*out.get(evidence_class, ()), lane.scheme)
    return out


#: The schemes a class's ESTABLISHING evidence may include, and the schemes its FALSIFIER
#: speaks (ADR-MCPRE-068 §4.1, N4). A `proved` unit's prover run and its proof-obligation
#: probe are one lane; a `tested` unit's battery and its mutation probe are two.
ESTABLISHING_SCHEME = _schemes_by_class("establishes")
FALSIFIER_SCHEME = _schemes_by_class("falsifies")

assert HOST_LANES | EXTRACTION_LANES == {lane.name for lane in FORMAL}
assert not (HOST_LANES & EXTRACTION_LANES)
assert all(lane.phase is None for lane in HYGIENE)
assert SCOPABLE_LANES <= HOST_LANES


def selftest() -> int:
    failures = 0

    def case(label: str, ok: bool, detail: object = None) -> None:
        nonlocal failures
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            failures += 1
            print(f"        got {detail!r}")

    v0 = {"class": "V0", "evidence": ["test://a/b", "mutation://a"]}
    v1 = {"class": "V1", "evidence": ["test://a/b"]}
    v2 = {"class": "V2", "evidence": ["lean://m", "test://a/b"]}
    case("a declared scheme claims its lane", claims(v0, "test") and claims(v0, "mutation"))
    case("an undeclared scheme does not", not claims(v0, "structural"))
    case("lean:// claims generated-model", claims(v2, "generated-model") and claims(v2, "lean"))
    case("a hygiene lane is claimed by nobody", not claims(v0, "assumptions"))
    case("a V0 unit owes mutation only because it declares it", required(v0, "mutation") and not required(v1, "mutation"))
    case("verus is required by the tier alone", required(v1, "verus") and not required(v0, "verus"))
    case("lean is required of V2 only with lean://", required(v2, "lean") and not required({"class": "V2", "evidence": []}, "lean"))
    case("a hygiene lane is never required", not required(v0, "assumptions"))
    case("every formal lane is in exactly one phase", HOST_LANES | EXTRACTION_LANES == {l.name for l in FORMAL} and not HOST_LANES & EXTRACTION_LANES)
    case("the extraction lanes are not scopable", not (SCOPABLE_LANES & EXTRACTION_LANES))
    case(
        "the class scheme maps",
        ESTABLISHING_SCHEME == {"tested": ("test://",), "structural": ("structural://",), "measured": ("measured://",), "proved": ("verus://", "lean://")}
        and FALSIFIER_SCHEME == {"tested": ("mutation://",), "structural": ("structural://",), "proved": ("verus://", "lean://")},
        (ESTABLISHING_SCHEME, FALSIFIER_SCHEME),
    )
    case("measured takes no falsifier scheme", "measured" not in FALSIFIER_SCHEME)
    case("every row names an entry point", all(lane.script for lane in LANES))
    if failures:
        print(f"lanes: SELFTEST FAILED ({failures})")
        return 1
    print("lanes: selftest passed")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else 0)
