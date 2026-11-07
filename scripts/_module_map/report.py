# SPDX-License-Identifier: Apache-2.0
"""The map's report: cross-plane counts and the runtime-into-composition edges."""

from __future__ import annotations

from collections import defaultdict

from _module_map.config import COMPOSITION, LEGITIMATE, MISPLACED_OWNERSHIP, PLANE_OF, PLANES

Graph = dict[str, dict[str, set[str]]]
Edge = tuple[str, str, set[str]]


def _symbols(syms: set[str]) -> str:
    return ", ".join(sorted(syms)) or "(module import)"


def print_edges(graph: Graph) -> None:
    print("EVERY PRODUCTION EDGE\n")
    for a in sorted(graph):
        for b, syms in sorted(graph[a].items()):
            print(f"  {a:26} -> {b:26} {_symbols(syms)}")


def _crosses(pa: str | None, pb: str | None) -> bool:
    """Both modules are classified and they sit in different planes."""
    return bool(pa and pb) and pa != pb


def cross_plane(graph: Graph) -> dict[tuple[str, str], int]:
    cross: dict[tuple[str, str], int] = defaultdict(int)
    for a, tos in graph.items():
        for b in tos:
            pa, pb = PLANE_OF.get(a), PLANE_OF.get(b)
            if _crosses(pa, pb):
                cross[(pa, pb)] += 1
    return cross


def print_cross_plane(cross: dict[tuple[str, str], int]) -> None:
    print("CROSS-PLANE EDGES")
    for (pa, pb), n in sorted(cross.items(), key=lambda kv: -kv[1]):
        mark = "   <-- into composition" if pb in COMPOSITION else ""
        print(f"  {n:3d}  {pa:14} -> {pb}{mark}")


def runtime_into_composition(graph: Graph) -> tuple[list[Edge], list[Edge]]:
    """(misplaced, legitimate) edges from a runtime plane into a composition plane."""
    misplaced: list[Edge] = []
    legit: list[Edge] = []
    for a, tos in sorted(graph.items()):
        if PLANE_OF.get(a) in COMPOSITION:
            continue
        into = [(b, syms) for b, syms in sorted(tos.items()) if PLANE_OF.get(b) in COMPOSITION]
        for b, syms in into:
            (legit if (a, b) in LEGITIMATE else misplaced).append((a, b, syms))
    return misplaced, legit


def print_misplaced(misplaced: list[Edge]) -> None:
    print(f"\n  MISPLACED RESPONSIBILITY — the reduction target ({len(misplaced)})")
    for a, b, syms in misplaced:
        print(f"\n    {a} -> {b}")
        print(f"      symbols: {_symbols(syms)}")
        for sym in sorted(s for s in syms if s in MISPLACED_OWNERSHIP):
            why, owner = MISPLACED_OWNERSHIP[sym]
            print(f"      {sym}: {why}")
            print(f"        proposed owner: {owner}")


def print_legitimate(legit: list[Edge]) -> None:
    print(f"\n  LEGITIMATE — excluded, with the reason reviewable ({len(legit)})")
    for a, b, syms in legit:
        print(f"\n    {a} -> {b}  [{', '.join(sorted(syms))}]")
        print(f"      {LEGITIMATE[(a, b)]}")


def print_reduction_targets(misplaced: list[Edge]) -> None:
    by_target: dict[str, int] = defaultdict(int)
    for _, b, _ in misplaced:
        by_target[b] += 1
    print(
        "\n\nREDUCTION TARGET BY OWNER: "
        + ", ".join(f"{k}={v}" for k, v in sorted(by_target.items()))
    )


def print_map(graph: Graph, module_count: int) -> None:
    total = sum(len(v) for v in graph.values())
    print(f"{module_count} modules, {total} production edges, {len(PLANES)} planes\n")
    print_cross_plane(cross_plane(graph))
    print("\nRUNTIME -> COMPOSITION EDGES")
    misplaced, legit = runtime_into_composition(graph)
    print_misplaced(misplaced)
    print_legitimate(legit)
    print_reduction_targets(misplaced)
