"""The Phase-1 correction records, and the four shapes read off what each one moved."""
import json
from typing import NamedTuple

from _phase1_tree import REPO

# Shape is a property of WHAT MOVED, so it is read off the record rather than asserted.
# Three distinctions, and the third is the one a components-only reading loses:
#
#   theorem_claim present            the SUBJECT's own statement or scope misdescribed
#   dependencies only, depends_on    the claim was right; the graph lacked the premise
#   dependencies only, prose field   a PREMISE was misdescribed, and the correction
#                                    reaches the root only because a premise digest moved
#
# A root can appear under more than one shape; it carried more than one kind of defect.
PROSE = {"statement", "security_consequence", "scope"}


class Shapes(NamedTuple):
    graph: set
    subject_prose: set
    premise_prose: set


def correction_records(out):
    recs = []
    for p in sorted((REPO / "verification/claim-corrections").glob("*.json")):
        d = json.loads(p.read_text())
        recs.append({"file": p.name, "theorem": d.get("subject"),
                     "components": d.get("changed_components"),
                     "corrections": [c.get("field") for c in d.get("corrections", [])],
                     "from": d.get("from_fingerprint"), "to": d.get("to_fingerprint")})
    out["claim_corrections"] = recs
    out["claim_correction_count"] = sum(len(r["corrections"]) for r in recs)
    out["dependency_corrections"] = sum(
        1 for r in recs for f in r["corrections"] if f == "depends_on")
    return recs


def correction_shapes(out, recs) -> Shapes:
    shape_graph, shape_subject_prose, shape_premise_prose = set(), set(), set()
    for r in recs:
        comps = set(r["components"] or ())
        fields = set(r["corrections"] or ())
        if "theorem_claim" in comps:
            shape_subject_prose.add(r["theorem"])
        if "depends_on" in fields:
            shape_graph.add(r["theorem"])
        if comps == {"theorem_dependencies"} and (fields & PROSE):
            shape_premise_prose.add(r["theorem"])
    out["shape_graph_incomplete"] = sorted(shape_graph)
    out["shape_claim_misdescribed"] = sorted(shape_subject_prose)
    out["shape_premise_misdescribed"] = sorted(shape_premise_prose)
    corrected = shape_graph | shape_subject_prose | shape_premise_prose
    out["roots_with_no_correction"] = [r for r in out["roots"] if r not in corrected]
    return Shapes(shape_graph, shape_subject_prose, shape_premise_prose)
