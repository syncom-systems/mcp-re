# SPDX-License-Identifier: Apache-2.0
"""An attestation: a successful check as a record of exactly what it was checked against, and
the loader that drops anything it cannot read."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

@dataclass(frozen=True)
class Attestation:
    """A successful check, as a record of exactly what it was checked against.

    `evidence` carries each lane's result. A `verus: fail` makes the unit BLOCKED rather
    than dirty: a failed proof is not "needs review again", it is "no freshness may be
    issued from here, and nothing downstream may inherit any" (§Case C).
    """

    unit_id: str
    fingerprint: str
    components: dict
    evidence: dict = field(default_factory=dict)

    @staticmethod
    def from_json(raw: dict) -> "Attestation":
        return Attestation(
            unit_id=raw["unit_id"],
            fingerprint=raw["fingerprint"],
            components=raw.get("components", {}),
            evidence=raw.get("evidence", {}),
        )


def load_attestations(store: Path) -> dict[str, Attestation]:
    """Every attestation in `store`, keyed by unit id.

    An unreadable or malformed record is DROPPED rather than repaired. The unit then has no
    attestation, so it derives to `UNKNOWN` — which is what "a cache whose provenance
    cannot be established" must mean (§2).
    """
    out: dict[str, Attestation] = {}
    if not store.exists():
        return out
    for path in sorted(store.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            attestation = Attestation.from_json(raw)
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
        out[attestation.unit_id] = attestation
    return out
