# SPDX-License-Identifier: Apache-2.0
"""Loading and validating the trusted-assumption registry."""

from __future__ import annotations

from _assumption_sites import validate_sites
from _premise import class_problem
from _premise import is_live
from _premise import registration_problems
from _record_rules import reject_unknown, require
from _registries import ManifestError
import _record_rules
import _registries


ASSUMPTIONS_TOML = _registries.path("assumptions")


#: The premise registry's own schema. Bumped to 2 by ADR-MCPRE-068 Phase 0C, which made
#: `premise_class` required of every live record.
#:
#: Enforced for the same reason `SCHEMA_VERSION` is enforced for `verification.toml`: a
#: registry written against schema 1 loading silently under schema-2 tooling would be read
#: as a fully typed estate with 47 untyped records in it. `_fingerprint.assumption_digest`
#: hashes each entry whole, so the new fields re-digest every premise and dirty every unit
#: in their scope — that invalidation is the schema change being handled rather than
#: tolerated.
ASSUMPTIONS_SCHEMA_VERSION = 2


#: The URI forms an assumption's `scope` may take. A scope entry that matches neither is a
#: typo that scopes the assumption to nothing while looking like a registration, which is
#: the same failure as a mistyped key: it must not read as an absent declaration.
_SCOPE_PREFIXES = ("unit://", "boundary://")


_ASSUMPTION_KEYS = {
    "id",
    "description",
    "justification",
    "scope",
    "owner",
    "introduced_by",
    "review_requirement",
    "affected_contracts",
    "tool_specific_mechanism",
    "sites",
    # ADR-MCPRE-068 §7, C1-C5. `premise_class` is required of every LIVE premise and
    # refused on a withdrawn one; the other two are required by exactly one class each and
    # refused on the others, because a field nothing reads is a declaration that looks like
    # coverage. `_premise` owns all three rules.
    "premise_class",
    "boundary_owner",
    "discharging_event",
    # r12 Ruling 39 §4: the premise a `model-registration` takes its meaning from.
    "interpreted_by",
}


#: `sites` is the one OPTIONAL key, and its absence is not a default — it is the
#: fail-closed direction. An assumption with no `sites` registers no seam, so a premise
#: whose sites nobody has decided reads as trusting nothing rather than as trusting
#: whatever the mechanism kind happens to appear in next. It is therefore excluded from
#: the required set: making it required would force an entry to name a seam before the
#: decision about which seams it covers has been taken, which is how the kind-level rule
#: it replaces came to license every future site.
#: The three ADR-MCPRE-068 fields are conditional rather than unconditional, so they are
#: not in the unconditional required set: `_premise.class_problem` decides which of them
#: this entry owes from the class it declares and from whether it is live at all.
_ASSUMPTION_REQUIRED = set(_ASSUMPTION_KEYS) - {
    "sites",
    "premise_class",
    "boundary_owner",
    "discharging_event",
    "interpreted_by",
}


def load_assumptions(*, tree_checks: bool = True) -> dict:
    """Load and validate the trusted-assumption registry."""
    doc = _record_rules.load_registry(ASSUMPTIONS_TOML)
    where = "assumptions.toml"
    _validate_assumptions_header(where, doc)
    seen: set[str] = set()
    for index, entry in enumerate(doc.get("assumption", [])):
        _validate_assumption(f"{where} [[assumption]] #{index}", entry, seen, tree_checks)
    problems = registration_problems(doc)
    if problems:
        raise ManifestError(f"{where}: " + "; ".join(problems))
    return doc


def _validate_assumptions_header(where: str, doc: dict) -> None:
    """The registry's own keys and schema version."""
    reject_unknown(where, doc, {"schema_version", "assumption"})
    require(where, doc, {"schema_version"})
    if doc["schema_version"] != ASSUMPTIONS_SCHEMA_VERSION:
        raise ManifestError(
            f"{where}: schema_version {doc['schema_version']} but this tooling implements "
            f"{ASSUMPTIONS_SCHEMA_VERSION}. A premise registry written against an older "
            f"schema would load with untyped records reading as typed ones."
        )


def _validate_assumption(awhere: str, entry: dict, seen: set[str], tree_checks: bool) -> None:
    """Every admission rule one `[[assumption]]` record owes, in the order they are checked."""
    reject_unknown(awhere, entry, _ASSUMPTION_KEYS)
    require(awhere, entry, _ASSUMPTION_REQUIRED)
    if entry["id"] in seen:
        raise ManifestError(
            f"{awhere}: duplicate assumption id {entry['id']!r}. Ids are never reused "
            f"— a reused id makes two different trusted claims indistinguishable in "
            f"the review history."
        )
    seen.add(entry["id"])
    _require_resolvable_scope(awhere, entry)
    if tree_checks:
        validate_sites(awhere, entry)
    _require_boundary_edge(awhere, entry)
    # ADR-MCPRE-068 §7. Computable from ONE record in isolation, which is what keeps it
    # loader-stage and therefore merge-fatal: a malformed premise declaration is a lie
    # about what is trusted, and malformed has always been fatal here. Whether an
    # OBSERVABLE obligation has already come true is a different question — it needs
    # the other registries and the tree — and lives in `check-assumptions`.
    problem = class_problem(awhere, entry, is_live(entry))
    if problem is not None:
        raise ManifestError(problem)


def _require_resolvable_scope(awhere: str, entry: dict) -> None:
    """Every scope entry is a `unit://` or `boundary://` URI the tooling can resolve."""
    for target in entry.get("scope", []):
        if not str(target).startswith(_SCOPE_PREFIXES):
            raise ManifestError(
                f"{awhere}: scope entry {target!r} is neither `unit://<id>` nor "
                f"`boundary://<id>`. A scope the tooling cannot resolve trusts the "
                f"assumption nowhere while reading as a registration."
            )


def _require_boundary_edge(where: str, entry: dict) -> None:
    """Every live assumption names the boundary it crosses — the v0.17 TCB slice.

    `scope` is the ONE canonical direction of this relation, and it always accepted a
    `boundary://` target. What it did not do was require one, and the consequence was
    measured rather than supposed: of forty-one registered premises, exactly ONE named a
    boundary. `boundary_class_violations` therefore consulted a relation that was almost
    entirely unpopulated, so the cap could not fire for any boundary nobody had happened to
    write down — an enforcement that was live, correct, and reaching almost nothing.

    An unpopulated relation is worse than an absent one. Absent, a reader asks where the
    trust inventory is; unpopulated, the tooling answers the question with silence that
    reads like a clean result.

    A TOMBSTONE is the one exemption, and it is exempt by having an EMPTY scope rather than
    by being named in a list here. A withdrawn assumption trusts nothing — that is what
    withdrawing it meant — so giving it a boundary edge would make a retired premise read as
    a live one, which is the same defect pointed the other way.
    """
    scope = [str(target) for target in entry.get("scope", [])]
    if not scope:
        return
    if any(target.startswith("boundary://") for target in scope):
        return
    raise ManifestError(
        f"{where}: assumption {entry['id']} names no `boundary://<id>` in its scope. Every "
        f"live premise crosses something — foreign code, a service, the language runtime, "
        f"or this repository's own behaviour where the lane stops at it — and the boundary "
        f"is what tells a reader how far the claim above it reaches. Name the boundary it "
        f"crosses, or empty the scope if the premise is withdrawn."
    )
