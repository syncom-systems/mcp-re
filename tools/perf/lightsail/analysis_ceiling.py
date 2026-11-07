# SPDX-License-Identifier: Apache-2.0
"""The one-line ceiling answer, decided by the predeclared rules over the Phase B sweep."""

from __future__ import annotations


def _indeterminate(why: str) -> dict:
    return {"statement": "CEILING ATTRIBUTION: INDETERMINATE", "why": why}


def _plateau_is_stable(tail: list[dict], rows: list[dict]) -> bool:
    """Two consecutive plateau points at the top of the curve, each stable."""
    stable_tail = all(next(r for r in rows if r["cores"] == c["cores"])["stable"] for c in tail)
    return len(tail) == 2 and all(c["plateau"] for c in tail) and stable_tail


def _reached(top: dict, curve: dict, crows: list[dict]) -> dict:
    knee_n = curve.get("plateau_from")
    ceiling = max(c["throughput"] for c in crows if c["cores"] >= (knee_n or 0))
    return {"statement": f"PROXY CEILING: REACHED — ~{ceiling:.0f} rps, flat from {knee_n} cores",
            "ceiling_rps": ceiling, "plateau_from_cores": knee_n,
            "limiting_component": top["attribution"]["label"],
            "confidence": top["attribution"]["confidence"], "why": top["attribution"]["why"]}


def ceiling_statement(b_scaling: dict | None) -> dict:
    """The one-line answer, decided by the predeclared rules over the Phase B scaling sweep."""
    if not b_scaling or not b_scaling.get("rows"):
        return _indeterminate("no Phase B scaling sweep was measured")
    rows = b_scaling["rows"]
    top = rows[-1]
    label = top["attribution"]["label"]
    curve = b_scaling.get("curve") or {}
    if label in {"INDETERMINATE", "CLIENT_LIMITED", "UNATTRIBUTED"} or top["rps_proxy_median"] is None:
        return _indeterminate(f"the top of the sweep ({top['cores']} cores) is {label}: {top['attribution']['why']}")
    crows = curve.get("rows", [])
    tail = crows[-2:] if len(crows) >= 2 else []
    if _plateau_is_stable(tail, rows):
        return _reached(top, curve, crows)
    if curve.get("still_scaling_at_top"):
        return {"statement": "PROXY CEILING: NOT REACHED ON THIS HOST", "limiting_component": label,
                "why": f"incremental efficiency at the top of the sweep is still >= 0.5 ({top['cores']} cores, {label})"}
    return _indeterminate("the curve bends at the top but the plateau rule (two consecutive stable plateau points) is not met")
