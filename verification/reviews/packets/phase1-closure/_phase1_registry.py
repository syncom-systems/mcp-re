"""Closure numbers read from the policy registries: theorems, units, premises, N1 obligations."""
import collections
import json
import sys
from typing import NamedTuple

from _phase1_tree import load, sh


class Registries(NamedTuple):
    theorems: list
    units: list


def head_state(out):
    out["sha"] = sh("git", "rev-parse", "HEAD").stdout.strip()
    out["main_sha"] = sh("git", "rev-parse", "origin/main").stdout.strip()
    out["dirty"] = bool(sh("git", "status", "--porcelain").stdout.strip())
    out["census"] = json.loads(
        sh(sys.executable, "tools/verification/evidence-class-census", "--json").stdout)


def _premises(out, assume):
    prem = assume.get("assumption", [])
    live = [a for a in prem if a.get("scope")]
    withdrawn = [a for a in prem if not a.get("scope")]
    out["premises_total"] = len(prem)
    out["premises_live"] = len(live)
    out["premises_withdrawn"] = [a["id"] for a in withdrawn]
    out["premise_classes"] = dict(collections.Counter(a["premise_class"] for a in live))


def _n1_obligations(out, debt):
    out["n1_open"] = len(debt)
    out["n1_by_effective"] = dict(collections.Counter(r["effective_severity"] for r in debt))
    out["n1_root_reachable"] = sum(1 for r in debt if r.get("root_reachable"))
    out["n1_not_root_reachable"] = sum(1 for r in debt if not r.get("root_reachable"))
    out["n1_by_status"] = dict(collections.Counter(r.get("status") for r in debt))
    out["n1_successor_rows"] = [r["unit"] for r in debt if r.get("succeeds")]


def registry_numbers(out) -> Registries:
    thmdoc = load("verification/policy/theorems.toml")
    theorems = thmdoc["theorem"]
    verif = load("verification/policy/verification.toml")["unit"]
    assume = load("verification/policy/assumptions.toml")
    debt = load("config/assurance-obligation-debt.toml")["obligation"]

    out["theorems_total"] = len(theorems)
    out["roots"] = list(thmdoc["root_theorems"])
    out["units_total"] = len(verif)
    # --- evidence class by PROPOSITION, as the registries state it ---
    out["evidence_classes"] = dict(collections.Counter(u.get("evidence_class", "(unset)") for u in verif))
    _premises(out, assume)
    _n1_obligations(out, debt)
    return Registries(theorems, verif)
