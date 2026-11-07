"""Multi-proposition owner residue and the gates, measured not inferred."""
import collections
import sys

from _phase1_tree import sh

GATES = (("claim_surface", ["scripts/claim_surface_gate.py"]),
         ("assurance_obligation", ["scripts/assurance_obligation_gate.py"]),
         ("check_generated", ["tools/verification/check-generated"]),
         ("root_completeness", ["tools/verification/review", "--root-completeness"]))


def unit_fanout(out, registries):
    """Reported as fan-out rather than judged: a unit named by more than one theorem is
    where a second independently describable authority would hide. ADR-MCPRE-061
    question 2 was asked of each in the per-root packets; this is the population those
    answers quantify over."""
    fanout = collections.Counter(u for th in registries.theorems
                                 for u in (s.split("://", 1)[-1] for s in th.get("supported_by", [])))
    out["units_named_by_multiple_theorems"] = {u: n for u, n in sorted(fanout.items()) if n > 1}
    out["units_named_by_no_theorem"] = sorted({u["id"] for u in registries.units} - set(fanout))


def gates(out):
    for name, cmd in GATES:
        r = sh(sys.executable, *cmd)
        out.setdefault("gates", {})[name] = {
            "rc": r.returncode,
            "tail": (r.stdout or r.stderr).strip().splitlines()[-6:],
        }
