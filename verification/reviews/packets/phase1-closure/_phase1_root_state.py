"""Per-root FINAL STATE and the REASON it reached that state.

"87 obligations remain" is not a Phase-2 input; the reason each root ended where it
did is. Five reasons, and a root may carry more than one -- it had more than one
kind of defect. Derived, not asserted: the correction records give the first three,
and the baseline registry gives the fourth.
"""
from typing import NamedTuple

from _phase1_tree import sh, tomllib

PHASE1_BASE = "c8c506e1"   # Phase 0E, the commit N1 was switched on at


class UnitMovement(NamedTuple):
    reclassified: list
    added: list
    formal_new: list


def read_baseline(out):
    base_units = {}
    try:
        blob = sh("git", "show", PHASE1_BASE + ":verification/policy/verification.toml").stdout
        base_units = {u["id"]: u for u in tomllib.loads(blob)["unit"]}
    except Exception as exc:                      # a shallow clone has no baseline to read
        out["baseline_read_error"] = str(exc)
    out["baseline_sha"] = PHASE1_BASE
    out["baseline_units"] = len(base_units)
    return base_units


def closure(bydep, root):
    """Every theorem `root` depends on, so a reason can be attributed to the root it reached."""
    seen, stack = set(), [root]
    while stack:
        cur = stack.pop()
        for dep in bydep.get(cur, ()):
            if dep not in seen:
                seen.add(dep)
                stack.append(dep)
    return seen


def unit_movement(units, byunit, base_units) -> UnitMovement:
    reclassified, added = [], []
    for uid in sorted(units):
        now = byunit.get(uid, {}).get("evidence_class")
        was = base_units.get(uid, {}).get("evidence_class") if base_units else None
        if uid not in base_units and base_units:
            added.append(uid)
        elif was is not None and was != now:
            reclassified.append(f"{uid}: {was} -> {now}")
    # A split renames the unit, so a reclassification almost never shows as one id
    # changing class: it shows as the old id vanishing and a new carrier appearing.
    # The honest test is therefore what KIND of carrier Phase 1 added. A new
    # `structural` or `proved` unit means a proposition that stood as behavioural
    # now has the carrier its statement always implied.
    formal_new = sorted(u for u in added if byunit.get(u, {}).get("evidence_class") != "tested")
    return UnitMovement(reclassified, added, formal_new)


def reasons_for(root, shapes, movement):
    reasons = []
    if root in shapes.graph:
        reasons.append("graph corrected")
    if root in shapes.subject_prose:
        reasons.append("subject misdescribed, corrected")
    if root in shapes.premise_prose:
        reasons.append("premise correction propagated")
    if movement.reclassified or movement.formal_new:
        reasons.append("evidence class corrected")
    elif movement.added:
        reasons.append("establishment completed")
    return reasons or ["already correct"]


def root_state(out, registries, shapes, base_units):
    bydep = {t["id"]: t.get("depends_on", []) for t in registries.theorems}
    byunit = {u["id"]: u for u in registries.units}
    supports = {t["id"]: [s.split("://", 1)[-1] for s in t.get("supported_by", [])]
                for t in registries.theorems}
    state = {}
    for r in out["roots"]:
        fam = closure(bydep, r) | {r}
        units = {u for th in fam for u in supports.get(th, ())}
        movement = unit_movement(units, byunit, base_units)
        state[r] = {
            "reasons": reasons_for(r, shapes, movement),
            "closure_theorems": len(fam),
            "closure_units": len(units),
            "units_new_since_baseline": len(movement.added),
            "units_reclassified": movement.reclassified,
            "formal_carriers_added": movement.formal_new,
        }
    out["root_state"] = state
