# SPDX-License-Identifier: Apache-2.0
"""The two modes that read the build graph: the verdict, and the crate/license inventory."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

from _supply_chain.checks import (
    check_advisories,
    check_bans,
    check_licenses,
    check_policy_keys,
    check_sources,
)
from _supply_chain.config import LOCK, MODULE, POLICY
from _supply_chain.graph import Key, build_graph, crate_licenses, lock_packages, repo_key, resolve_edges
from _supply_chain.index import check_yanked


def inventory() -> int:
    """The graph as a table: every crate the build reaches, with its license."""
    packages = lock_packages(LOCK.read_text())
    repos = build_graph()
    licenses = crate_licenses(repos)
    rows = sorted(k for k in (repo_key(s, packages) for s in repos.values()) if k)
    for name, version in rows:
        print(f"{name}\t{version}\t{licenses.get(f'{name}-{version}', '')}")
    print(f"{len(rows)} crate(s)", file=sys.stderr)
    return 0 if rows else 1


def _split_graph(repos: dict[str, str], packages: dict) -> tuple[list[Key], list[str]]:
    """The build graph's crates the lock pins, and the spellings it does not."""
    graph, unknown = [], []
    for spelled in sorted(repos.values()):
        key = repo_key(spelled, packages)
        if key:
            graph.append(key)
        else:
            unknown.append(spelled)
    return graph, unknown


def _graph_problems(graph: list[Key], unknown: list[str]) -> list[str]:
    problems = [f"GRAPH: {u} is built but bazel/crates.lock does not pin it" for u in unknown]
    if not graph:
        problems.append("GRAPH: the build graph reached no third-party crate — assessing nothing is not a pass")
    return problems


def _advisory_problems(graph: list[Key], advisory_db: Path, policy: dict) -> list[str]:
    if not (advisory_db / "crates").is_dir():
        return [f"ADVISORIES: {advisory_db} is not a RustSec advisory-db checkout"]
    return check_advisories(graph, advisory_db, set(policy["advisories"]["ignore"]))


def _report(problems: list[str], duplicates: list[str], graph: list[Key]) -> int:
    for d in duplicates:
        print(f"supply-chain gate: note — duplicate versions (allowed): {d}")
    if problems:
        print(f"supply-chain gate: FAIL — {len(problems)} problem(s) over {len(graph)} crate(s)")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"supply-chain gate: OK — {len(graph)} crate(s) in the Bazel build graph: sources, "
          f"licenses, bans, RustSec advisories and yanked versions all pass "
          f"({len(duplicates)} allowed duplicate(s) listed above)")
    return 0


def verdict(advisory_db: Path) -> int:
    policy = tomllib.loads(POLICY.read_text())
    problems = check_policy_keys(policy)
    packages = lock_packages(LOCK.read_text())
    edges = resolve_edges(packages)
    repos = build_graph()
    graph, unknown = _split_graph(repos, packages)
    problems += _graph_problems(graph, unknown)

    problems += check_sources(graph, packages, policy["sources"]["allow-registry"])
    problems += check_licenses(graph, crate_licenses(repos), set(policy["licenses"]["allow"]))
    ban_problems, duplicates = check_bans(graph, edges, policy["bans"], MODULE.read_text())
    problems += ban_problems
    problems += _advisory_problems(graph, advisory_db, policy)
    problems += check_yanked(graph)
    return _report(problems, duplicates, graph)
