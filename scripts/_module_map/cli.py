# SPDX-License-Identifier: Apache-2.0
"""The map, or every edge with `--edges`; non-zero when a module has no plane."""

from __future__ import annotations

import sys

from _module_map.config import PLANE_OF
from _module_map.graph import build_map
from _module_map.report import print_edges, print_map


def run() -> int:
    graph, modules = build_map()
    unclassified = sorted(m for m in modules if m not in PLANE_OF)
    if unclassified:
        print(f"UNCLASSIFIED MODULES (fix PLANES before trusting this map): {unclassified}\n")
    if "--edges" in sys.argv:
        print_edges(graph)
    else:
        print_map(graph, len(modules))
    return 1 if unclassified else 0
