# SPDX-License-Identifier: Apache-2.0
"""Where the registry lives, and the closed vocabulary of its rows."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
REGISTRY_REL = "config/assurance-obligation-debt.toml"
REGISTRY = REPO / REGISTRY_REL

sys.path.insert(0, str(REPO / "tools" / "verification"))

import _registries  # noqa: E402

STATUSES = ("unreviewed", "reviewed-action-required", "reviewed-exception")
REVIEWED = STATUSES[1:]

KEYS = {
    "unit",
    "obligation",
    "effective_severity",
    "direct_consequence_severity",
    "inherited_severity",
    "root_reachable",
    "status",
    "review_ref",
    "succeeds",
    "decomposition_ref",
}
OPTIONAL = {"review_ref", "succeeds", "decomposition_ref"}

#: The registry whose `paths` decide whether a successor refines the SAME production code.
#:
#: Read at the base revision rather than here, because that is the tree the predecessor's
#: obligation was measured over. A successor could otherwise be given the predecessor's
#: paths in the same commit that widens them.
UNITS_REL = _registries.relative("verification")
