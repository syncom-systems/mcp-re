"""The dependency graph: loading it, ordering files leaf-first, and the reverse set."""
from __future__ import annotations

import json
from collections import defaultdict


def _edges(files: list[str], deps: dict[str, list[str]]) -> tuple[dict, dict]:
    """(in-degree per file, dependents per file), over imports within `files`."""
    fileset = set(files)
    indeg = {f: 0 for f in files}
    dependents: dict[str, list[str]] = defaultdict(list)
    for f in files:
        for d in [d for d in deps.get(f, []) if d in fileset]:
            dependents[d].append(f)
            indeg[f] += 1  # f depends on d → f waits for d
    return indeg, dependents


def _released_by(f: str, indeg: dict, dependents: dict) -> list[str]:
    """The dependents of `f` that have nothing left to wait for once `f` is placed."""
    freed = []
    for dep in sorted(dependents[f]):
        indeg[dep] -= 1
        if indeg[dep] == 0:
            freed.append(dep)
    return freed


def topo_order(files: list[str], deps: dict[str, list[str]], priority=None) -> list[str]:
    """Return files with dependencies before dependents (leaf-first).

    Edge file -> dep means `file` imports `dep`; deps must come first. Kahn's
    algorithm over the reversed graph. Cycles are broken deterministically by
    appending any remaining files in sorted order (a cycle has no valid leaf).

    Topology is a CONSTRAINT, not the objective: among the files that are ready
    at any step, `priority` picks which to emit. Without it the ready set is
    drained alphabetically, which buries a critical behind every migration whose
    name happens to sort earlier.
    """
    key = priority or (lambda f: (f,))
    indeg, dependents = _edges(files, deps)
    ready = sorted([f for f in files if indeg[f] == 0], key=key)
    order: list[str] = []
    while ready:
        f = ready.pop(0)
        order.append(f)
        ready += _released_by(f, indeg, dependents)
        ready.sort(key=key)
    placed = set(order)
    return order + sorted(f for f in files if f not in placed)


def load_deps(deps_path: str | None) -> tuple[dict, dict, dict]:
    """(deps, rdeps, importers) from the optional graph file.

    Accepts both shapes: the bare {file: [imports]} map, and the richer
    deps_graph.py output, which also carries the reverse edges and the
    monorepo-wide importer count that decides which gate a fix must pass."""
    if not deps_path:
        return {}, {}, {}
    with open(deps_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc, dict) and "deps" in doc:
        return doc.get("deps", {}), doc.get("rdeps", {}), doc.get("importers", {})
    return doc, {}, {}


def related_of(f: str, deps: dict, rdeps: dict) -> list[str]:
    """The reverse deps (files that import `f`) — the indirect blast radius to
    re-scan alongside it."""
    if rdeps:
        return sorted(rdeps.get(f, []))
    if deps:
        return sorted(x for x, imps in deps.items() if f in imps)
    return []
