# SPDX-License-Identifier: Apache-2.0
"""Validating the declaration and every stored record. No measurement, no Docker."""

from __future__ import annotations

import json
from pathlib import Path

from _slo_evidence.classes import class_defects, hardware_classes
from _slo_evidence.config import SCHEMA
from _slo_evidence.store import evidence_store, record_path
from _slo_evidence.surface import performance_surface


def _record_defect(path: Path) -> str | None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return f"{path.name}: not JSON ({exc})"
    if doc.get("schema") != SCHEMA:
        return f"{path.name}: schema {doc.get('schema')!r}, expected {SCHEMA!r}"
    if record_path(doc["performance_surface"], doc["measurement_context_digest"]).name != path.name:
        return f"{path.name}: filename does not derive from the identity it carries"
    return None


def check() -> int:
    """Validate the declaration and every stored record. No measurement, no Docker."""
    surface, digests = performance_surface()
    store = evidence_store()
    stored = sorted(store.glob("*.json")) if store.is_dir() else []
    bad = [defect for defect in map(_record_defect, stored) if defect]
    bad.extend(class_defects())
    for line in bad:
        print(f"  ✗ {line}")
    if bad:
        print(f"slo-evidence-identity: FAILED ({len(bad)} defect(s))")
        return 1
    classes = hardware_classes()
    anchored = sum(1 for entry in classes.values() if entry["regression_anchor"])
    print(
        f"slo-evidence-identity: OK — {len(digests)} declared input(s), all git-tracked; "
        f"surface {surface[:23]}…; {len(stored)} attested result(s); {len(classes)} declared "
        f"hardware class(es), {anchored} anchored"
    )
    return 0
