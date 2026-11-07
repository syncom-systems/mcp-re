# SPDX-License-Identifier: Apache-2.0
"""The evidence components of a unit fingerprint: tests, probes, contracts and assumptions.

What the unit's evidence CLAIMS and which of it was actually selected: the effective test
selection and the bytes of the integration targets it runs, the registry records scoped to
the unit (probes, measurements), the producer contracts it consumes, and the assumptions it
trusts. Each is measured rather than labelled, so shrinking the evidence moves the digest.
"""

from __future__ import annotations

import functools

import _registries
import _rust_targets
import _tree
from _ecosystems import test_project_for
from _fingerprint_digest import assumption_digest
from _fingerprint_digest import canonical_digest
from _fingerprint_digest import digest_paths
from _fingerprint_digest import record
from _lanes import claims
from _manifest import REPO_ROOT

#: The committed build-graph table every Rust label resolves through.
RUST_TARGETS_TABLE = _rust_targets.TABLE.relative_to(REPO_ROOT).as_posix()


def trusted_assumptions(unit_id: str, assumptions: dict) -> dict[str, str]:
    """Each in-scope assumption's id, mapped to a digest of WHAT IT TRUSTS.

    Ids alone would let an assumption be rewritten — its description widened, its scope
    extended, its mechanism swapped — without any unit deriving DIRTY_ASSUMPTION. The
    registry entry is the trusted claim, so the entry's content is what participates.
    """
    out: dict[str, str] = {}
    for entry in assumptions.get("assumption", []):
        if f"unit://{unit_id}" not in entry.get("scope", []):
            continue
        out[entry["id"]] = assumption_digest(entry)
    return out


def test_selection(unit: dict) -> dict:
    """WHICH tests were selected: the resolved project, the exact symbols, and each Rust
    test target as the build graph states it.

    Empty for a unit with no `test://` evidence — measured, and empty, which is a different
    claim from "not accounted for".

    The target rows are the build configuration the selection resolves in. A feature-gated
    control does not merely fail to run without its feature — it does not EXIST, so the same
    symbol under a target whose features changed is a different selection, and a target
    re-rooted at another crate selects different code. The label alone would not move when
    either happened; its row does.
    """
    if not claims(unit, "test"):
        return {}
    record(RUST_TARGETS_TABLE)
    labels = sorted({str(s).partition("#")[0] for s in unit.get("tested_symbols", [])})
    return {
        "project": test_project_for(unit),
        "symbols": sorted(str(s) for s in unit.get("tested_symbols", [])),
        "targets": {
            label: {"root": row["root"], "features": row["features"]}
            for label in labels
            for row in [_rust_targets.target(label)]
            if label.startswith("//") and row is not None
        },
    }


def test_source_patterns(unit: dict) -> list[str]:
    """The globs naming the integration-test targets this unit's selectors run."""
    if not claims(unit, "test"):
        return []
    record(RUST_TARGETS_TABLE)
    patterns: set[str] = set()
    for symbol in unit.get("tested_symbols", []):
        label = str(symbol).partition("#")[0]
        row = _rust_targets.target(label) if label.startswith("//") else None
        # A target built from a crate runs code in the unit's own `paths`; an integration
        # target's sources are its own, and the build graph lists them.
        if row is not None and not row["crate"]:
            patterns.update(row["srcs"])
    return sorted(patterns)


def test_sources(unit: dict) -> dict[str, str]:
    """The bytes of the integration-test targets this unit's selectors run.

    Without this, a control could keep its declared name and lose its body: the selector
    still resolves, the lane still reports a pass, and the fingerprint never moves. The
    name is the label; the file is the evidence.
    """
    return digest_paths(test_source_patterns(unit))


def consumed_contracts(unit: dict, doc: dict) -> list[str]:
    """The producer contracts this unit consumes, DERIVED from its incoming edges.

    One authority. The relation lives on the edge — which names the contract and the
    producer that exports it, and is refused unless that producer really does — so a unit
    field saying the same thing is a second answer that nothing reconciles. It was authored
    by no unit while nine edges named no contract, which is what a duplicate authority looks
    like before anyone notices: three representations that have never had to agree.

    In the fingerprint because a change in WHICH producer contract a unit consumes changes
    its dependency identity. `exported_contracts` carries the producer's side of the same
    relation.
    """
    return sorted(
        {
            edge["contract"]
            for edge in doc.get("edge", [])
            if edge["kind"] == "CONTRACT_CONSUMES" and edge["to"] == unit["id"]
        }
    )


def mutation_probes(unit_id: str) -> dict[str, str]:
    """Each probe scoped to this unit, mapped to a digest of WHAT IT PROVES.

    Ids alone would let a probe be hollowed out — its weakening softened, its `expect_red`
    widened to a control that fails for another reason — with no unit deriving DIRTY. The
    registry entry is the claim, so the entry's content is what participates. Same argument,
    and same shape, as `trusted_assumptions`.
    """
    return registry_entries("mutation-probes", "probe", unit_id)


def registry_entries(name: str, key: str, unit_id: str) -> dict[str, str]:
    """Each record in registry `name` scoped to this unit, digested WHOLE.

    The generalization of `mutation_probes`, and it exists because ADR-MCPRE-068 added two
    more registries with the same property: ids alone would let a record be hollowed out —
    a hostile construction softened into one that was never illegal, an expected error code
    widened, a measurement's protocol pointed at a different corpus — with no unit deriving
    DIRTY. The registry entry IS the claim, so the entry's content participates.
    """
    record(_registries.relative(name))
    rel = _registries.relative(name)
    if not _tree.current().is_file(rel):
        return {}
    return dict(_entries_by_unit(_tree.text(rel), key).get(unit_id, {}))


@functools.lru_cache(maxsize=16)
def _entries_by_unit(text: str, key: str) -> dict[str, dict[str, str]]:
    """Every `[[key]]` record of a registry's `text`, digested whole and grouped by unit.

    Once per distinct text: a fingerprint asks for every unit's records, and grouping the
    registry once is what lets that cost one pass rather than one per unit.
    """
    out: dict[str, dict[str, str]] = {}
    for record in _registries.parse(text, key).get(key, []):
        out.setdefault(record.get("unit"), {})[record["id"]] = canonical_digest(record)
    return out
