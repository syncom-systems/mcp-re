"""Finding-level checks: duplicate provenance (FND-002/003) and evidence refs (EVD-001)."""
from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass

from _reduce_model import problem


@dataclass(frozen=True)
class Provenance:
    problems: list
    clusters: dict
    unique_defects: int
    duplicates: int


class _Classes:
    """Union-find over finding ids and cluster labels. The smaller id is the root, so
    a class is named the same way however the edges arrive."""

    def __init__(self) -> None:
        self.parent: dict = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, x, y) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            self.parent[min(rx, ry)] = self.parent[max(rx, ry)] = min(rx, ry)


def _is_dangling(f: dict, findings: dict, ledger: dict) -> bool:
    target = f["duplicate_of"]
    if not target:
        return False
    return target not in findings and target not in ledger


def _dangling(findings: dict, ledger: dict | None, usable: bool) -> tuple:
    """`duplicate_of` is a REFERENCE to a finding; `cluster_id` is a LABEL for an
    equivalence class and refers to nothing. Only the reference can dangle, and
    that is decidable only against a stable ledger snapshot."""
    if not usable:
        return set(), []
    bad = [fid for fid, f in sorted(findings.items()) if _is_dangling(f, findings, ledger)]
    return set(bad), [problem("FND-002", finding_id=fid, detail=findings[fid]["duplicate_of"])
                      for fid in bad]


def _has_parent(findings: dict, node: str) -> bool:
    return node in findings and bool(findings[node]["duplicate_of"])


def _cycle_from(findings: dict, start: str) -> list:
    """The duplicate chain's cycle reached from `start`, or [] when it ends."""
    path, node = [], start
    while _has_parent(findings, node) and node not in path:
        path.append(node)
        node = findings[node]["duplicate_of"]
    return path[path.index(node):] if node in path else []


def _cycles(findings: dict) -> tuple:
    """The DIRECTED relation must be acyclic: `A dup B, B dup A` names no canonical
    finding. Union-find would quietly merge a cycle into one class, which is right
    for counting defects and wrong for provenance — so the cycle is found on the
    directed graph FIRST, and its edges are kept out of the union."""
    bad: set = set()
    out: list = []
    for start in sorted(findings):
        cycle = _cycle_from(findings, start)
        if cycle and not bad & set(cycle):
            bad |= set(cycle)
            out.append(problem("FND-003", detail=sorted(cycle)))
    return bad, out


def _clusters(findings: dict, bad_edges: set) -> dict:
    """`duplicate_of` and `cluster_id` are two spellings of the SAME relation once
    provenance is valid, so they are unioned, not prioritised: keying on
    cluster_id first left f002 (cluster "claim-x", duplicate_of f001) in a
    different group from f001, reporting two defects where there is one."""
    classes = _Classes()
    for fid, f in findings.items():
        classes.find(fid)
        if f["duplicate_of"] and fid not in bad_edges:
            classes.union(fid, f["duplicate_of"])
        if f["cluster_id"]:
            classes.union(fid, f["cluster_id"])
    clusters: dict = defaultdict(set)
    for fid in findings:
        clusters[classes.find(fid)].add(fid)
    return clusters


def duplicate_provenance(findings: dict, ledger: dict | None, usable: bool) -> Provenance:
    bad_edges, problems = _dangling(findings, ledger, usable)
    cycle_edges, cycle_problems = _cycles(findings)
    clusters = _clusters(findings, bad_edges | cycle_edges)
    duplicates = sum(1 for f in findings.values() if f["duplicate_of"])
    return Provenance(problems + cycle_problems, clusters, len(clusters), duplicates)


def unresolved_evidence(evidence_refs: dict, repo_root: str) -> tuple:
    """(unresolved refs, EVD-001 problems); refs resolve against `repo_root`."""
    unresolved: list = []
    problems: list = []
    for ref in sorted(evidence_refs):
        p = ref if os.path.isabs(ref) else os.path.join(repo_root, ref)
        if not os.path.exists(p):
            unresolved.append(ref)
            problems.append(problem("EVD-001", event_id=evidence_refs[ref], detail=ref))
    return unresolved, problems
