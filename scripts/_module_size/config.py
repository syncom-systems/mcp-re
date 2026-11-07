# SPDX-License-Identifier: Apache-2.0
"""The module-size register's vocabulary: threshold, statuses, fields, lifecycle, schema."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "verification"))

import _ratchet  # noqa: E402

REGISTRY_REL = "config/module-size-debt.toml"
REGISTRY = REPO / REGISTRY_REL
THRESHOLD = 200

#: ADR-MCPRE-061 §14 dispositions. Investigation status and disposition are separate facts:
#: a completed census must stay distinguishable from an unperformed one EVEN WHEN its
#: disposition is "decompose before any exception". Collapsing `reviewed-action-required`
#: into `unreviewed` would tell the next agent that nobody has looked.
STATUSES = {"unreviewed", "reviewed-exception", "reviewed-action-required"}

#: Both reviewed dispositions must name the record that adjudicated them. The field is
#: `review_ref`, not `exception_ref`: EX-002 is a completed census that DECLINED an
#: exception, so the reference is to an adjudication, not to a grant.
REVIEWED = {"reviewed-exception", "reviewed-action-required"}

#: The two halves of a ONE-SHOT upward-baseline authorization. They are a pair: a
#: `growth_from_prod_loc` with no record is an unevidenced claim, and a `growth_ref` with no
#: transition does not say WHICH increase was authorized.
GROWTH_FIELDS = {"growth_from_prod_loc", "growth_ref"}

#: Anything else in a `[[debt]]` table is a typo or a stale field name, and both fail.
ENTRY_FIELDS = {
    "path",
    "baseline_prod_loc",
    "baseline_sha",
    "status",
    "review_ref",
} | GROWTH_FIELDS

#: The permitted disposition transitions, as ADR-MCPRE-061 §14 defines the lifecycle.
#: Every one of them either preserves or increases what is known about a unit; none
#: returns it to "nobody has investigated this".
PERMITTED_TRANSITIONS = {
    ("unreviewed", "unreviewed"),
    ("unreviewed", "reviewed-exception"),
    ("unreviewed", "reviewed-action-required"),
    ("reviewed-action-required", "reviewed-action-required"),
    ("reviewed-action-required", "reviewed-exception"),
    ("reviewed-exception", "reviewed-exception"),
    # A re-census of a granted exception may find new work. Refusing this would force the
    # registry to assert that no work exists, which is the defect the lifecycle exists to
    # prevent — so it is permitted, unlike any move back toward `unreviewed`.
    ("reviewed-exception", "reviewed-action-required"),
}

#: The register's shape. `_ratchet` checks it; this gate decides only what it measures.
SCHEMA = _ratchet.Schema(
    table="debt",
    key="path",
    required=frozenset({"path", "baseline_prod_loc", "baseline_sha", "status"}),
    fields=frozenset(ENTRY_FIELDS),
    statuses=tuple(sorted(STATUSES)),
    reviewed=frozenset(REVIEWED),
    unknown_hint=(
        " — `exception_ref` was renamed to `review_ref` because a §14 record may also "
        "DECLINE an exception"
    ),
)
