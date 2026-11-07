# SPDX-License-Identifier: Apache-2.0
"""What a TRUSTED SEAM is — the single authority, shared by every consumer.

A seam is a place where a proof stops proving and starts trusting: an `uninterp` spec
function, an `external_body`, an `assume_specification`. Two questions in this repository
depend on recognising one, and they used to be answerable only inside `check-assumptions`:

  * IS EVERY SEAM REGISTERED?  — `check-assumptions`, the escape-hatch gate.
  * WHICH TRUST BOUNDARIES DOES A PROOF ACTUALLY CROSS? — `_manifest.boundary_class_violations`.

The second is why this module exists. R9-C022 asked whether six V1 units crossed
`boundary.crypto_primitives`, and the answer turns on the difference between a proof that
CONSUMES an unproved proposition beyond that boundary and one that merely COMPILES
alongside it. Only a seam distinguishes them, so the boundary rule needs the same notion of
"seam" the escape-hatch gate uses — and a second copy of these patterns would be a second
answer to what a seam is, diverging the first time one was updated.

It also owns the seam INVENTORY the escape-hatch gate and the registry cross-check both
read: `scan` and `live_sites` over the tree, `stale_sites` against the registry, the per-site
registration rule, and the vacuity rule at a proved symbol. Each takes the loaded registry
documents and the repository root it reads, so `check-assumptions` and `_registry_refs`
call one implementation rather than one hand-loading the other.

It imports nothing from this package but `_rust_source` and the `_seams_*` modules it is
assembled from: `_manifest` imports it.
"""

from __future__ import annotations

from _seams_inventory import (
    declared_seam_sites,
    EXCLUDED,
    Hit,
    live_sites,
    scan,
    scan_paths,
    SCANNED_SUFFIXES,
    stale_sites,
    unit_files,
)
from _seams_items import (
    declared_items,
    item_at,
    site_key,
)
from _seams_patterns import (
    code_of,
    files_with_seams,
    MECHANISMS,
    production_lines,
    PRODUCTION_MECHANISMS,
    seam_lines,
)
from _seams_registration import (
    is_registered,
    registered_by_unit,
)
from _seams_vacuity import (
    definition_pattern,
    definition_sites,
    proved_symbol_defects,
    SPECIFICATION_TEXT,
    VACUITY_AT_PROVED_SYMBOL,
)

__all__ = [
    "EXCLUDED",
    "Hit",
    "MECHANISMS",
    "PRODUCTION_MECHANISMS",
    "SCANNED_SUFFIXES",
    "SPECIFICATION_TEXT",
    "VACUITY_AT_PROVED_SYMBOL",
    "code_of",
    "declared_items",
    "declared_seam_sites",
    "definition_pattern",
    "definition_sites",
    "files_with_seams",
    "is_registered",
    "item_at",
    "live_sites",
    "production_lines",
    "proved_symbol_defects",
    "registered_by_unit",
    "scan",
    "scan_paths",
    "seam_lines",
    "site_key",
    "stale_sites",
    "unit_files",
]
