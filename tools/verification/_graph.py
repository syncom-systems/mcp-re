# SPDX-License-Identifier: Apache-2.0
"""The security evidence graph — ADR-MCPRE-059 §2-§6, Phase 4.

Freshness is DERIVED, never asserted. There is no mutable `clean = true` anywhere: a unit
is fresh only while every input its previous conclusion depended on still hashes the same.

## Why an attestation records components, not one hash

`ReviewFingerprint` is a single digest over every input, and a single digest can only say
"something moved". The states ADR-MCPRE-059 §5 requires — `DIRTY_SELF` versus
`DIRTY_CONTRACT` versus `DIRTY_DEPENDENCY` — are answers to *which* input moved, and a
reviewer needs that answer to know what work the change actually created. So an attestation
stores the components individually and derivation compares them one at a time.

The whole-fingerprint digest is still recorded, and still authoritative for "is this the
same evidence": if the components matched but the fingerprint did not, the encoding itself
changed, and that is `UNKNOWN`.

## Fail-closed everywhere

Missing attestation, unparsable record, unknown edge kind, a component the current schema
does not know how to compute — every one of them is dirty. There is no path in this module
from "I could not establish freshness" to `FRESH`, which is the property the entire design
rests on and the one that would be easiest to lose to a convenience.
"""

from __future__ import annotations

from _graph_attestation import Attestation, load_attestations
from _graph_derive import derive_unit_state
from _graph_evaluate import evaluate
from _graph_propagate import context_closure, propagate
from _graph_states import (
    COMPONENT_STATE,
    STATE_PRECEDENCE,
    STRUCTURAL_COMPONENT,
    UNRESOLVED_COMPONENT,
)

__all__ = [
    "COMPONENT_STATE",
    "STATE_PRECEDENCE",
    "STRUCTURAL_COMPONENT",
    "UNRESOLVED_COMPONENT",
    "Attestation",
    "context_closure",
    "derive_unit_state",
    "evaluate",
    "load_attestations",
    "propagate",
]
